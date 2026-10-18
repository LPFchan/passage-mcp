from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
from collections.abc import AsyncIterator
from contextvars import ContextVar

from mcp.server import CacheHint, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
import uvicorn

from .config import Config
from .store import AgeStore, InternalError
from .identity import header_values, identity_from
from .tenancy import TenantManager

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

_client: AgeStore | None = None
_tenants: TenantManager | None = None
_http_mode = False
_request_client: ContextVar[AgeStore | None] = ContextVar("passage_store", default=None)


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_FORMAT,
        stream=sys.stderr,
    )
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("uvicorn").setLevel(logging.WARNING)


def _require_client() -> AgeStore:
    if _http_mode:
        client = _request_client.get()
        if client is None:
            raise InternalError("No request vault selected")
        return client
    if _client is None:
        raise InternalError("Server not initialized")
    return _client


# -- request identity ------------------------------------------------------


class _IdentityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # This listener is reachable only through the gateway's loopback port.
        if scope["path"] == "/healthz" and scope["method"] == "GET":
            await self.app(scope, receive, send)
            return
        headers = header_values(scope.get("headers", []))
        identity = identity_from(headers)
        if identity is None:
            await JSONResponse({"error": "Gateway identity missing or malformed"}, status_code=401)(scope, receive, send)
            return
        path = scope["path"]
        api = path == "/api" or path.startswith("/api/")
        session = path == "/api/session" and scope["method"] == "GET"
        if api and not session:
            # Browser sends the decoded immutable subject as an UTF-8 header.
            # Header values in ASGI are Latin-1 byte-preserving strings.
            try:
                subject = headers.get("x-passage-subject", "").encode("latin1").decode("utf-8")
            except UnicodeError:
                subject = None
            if subject != identity["sub"]:
                await JSONResponse({"error": "Session subject mismatch"}, status_code=403)(scope, receive, send)
                return
            if scope["method"] not in {"GET", "HEAD", "OPTIONS"} and headers.get("origin") != "https://passage.lost.plus":
                await JSONResponse({"error": "Invalid request origin"}, status_code=403)(scope, receive, send)
                return
        scope.setdefault("state", {})["passage_identity"] = identity
        token = _request_client.set(None)
        try:
            if not session:
                if _tenants is None:
                    raise InternalError("Tenant manager not initialized")
                _request_client.set(await _tenants.get_store(identity["sub"]))
            await self.app(scope, receive, send)
        finally:
            _request_client.reset(token)


# -- lifespan --------------------------------------------------------------


def _build_lifespan(config_path: str, *, http: bool = False):
    @contextlib.asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        global _client, _tenants, _http_mode
        logger = logging.getLogger(__name__)
        logger.info("Loading config from %s", config_path)

        config = Config.from_path(config_path)
        logger.info(
            "Store %s, identity %s (allowed_folders=%s)",
            config.store_dir,
            config.identity_file,
            config.allowed_folders if config.allowed_folders is not None else "all",
        )

        _http_mode = http
        _client = AgeStore(config)
        try:
            if http:
                _tenants = TenantManager(config, _client)
            await _client.validate()
            logger.info("Startup validation passed")
            yield
        finally:
            if _client is not None:
                await _client.close()
                _client = None
            _tenants = None
            _http_mode = False

    return lifespan


# -- tools ----------------------------------------------------------------


def _register_tools(mcp_server: MCPServer) -> None:
    @mcp_server.tool()
    async def get_secret(folder: str, item_name: str) -> str:
        """Retrieve a secret value from the encrypted store."""
        return await _require_client().get_secret(folder, item_name)

    @mcp_server.tool()
    async def get_login(folder: str, item_name: str) -> dict:
        """Retrieve a full login entry (username and password) from the encrypted store."""
        return await _require_client().get_login(folder, item_name)

    @mcp_server.tool()
    async def list_secrets(folder: str | None = None) -> list[dict]:
        """List available secret names (never the values themselves)."""
        return await _require_client().list_secrets(folder)

    @mcp_server.tool()
    async def add_secret(folder: str, item_name: str, value: str) -> dict:
        """Add a new secret to a folder. The folder must already exist."""
        await _require_client().add_secret(folder, item_name, value)
        return {"ok": True}

    @mcp_server.tool()
    async def add_login(folder: str, item_name: str, username: str, password: str) -> dict:
        """Add a new login entry (username + password) to a folder."""
        await _require_client().add_login(folder, item_name, username, password)
        return {"ok": True}

    @mcp_server.tool()
    async def edit_secret(folder: str, item_name: str, value: str) -> dict:
        """Update an existing secret's value."""
        await _require_client().edit_secret(folder, item_name, value)
        return {"ok": True}

    @mcp_server.tool()
    async def delete_secret(folder: str, item_name: str) -> dict:
        """Soft-delete a secret (moves it to trash; recover with recover_secret)."""
        await _require_client().delete_secret(folder, item_name)
        return {"ok": True}

    @mcp_server.tool()
    async def recover_secret(folder: str, item_name: str) -> dict:
        """Recover a soft-deleted secret from trash."""
        await _require_client().recover_secret(folder, item_name)
        return {"ok": True}

    @mcp_server.tool()
    async def add_folder(folder: str) -> dict:
        """Create a new folder for organizing secrets."""
        await _require_client().add_folder(folder)
        return {"ok": True}

    @mcp_server.tool()
    async def delete_folder(folder: str) -> dict:
        """Delete an empty folder."""
        await _require_client().delete_folder(folder)
        return {"ok": True}

    @mcp_server.tool()
    async def list_trash() -> list[dict]:
        """List soft-deleted secrets currently in trash."""
        return await _require_client().list_trash()

    @mcp_server.tool()
    async def move_secret(folder: str, item_name: str, target_folder: str) -> dict:
        """Move a secret to a different folder."""
        await _require_client().move_secret(folder, item_name, target_folder)
        return {"ok": True}

    @mcp_server.tool()
    async def rename_secret(folder: str, item_name: str, new_name: str) -> dict:
        """Rename a secret (keeps the same value and folder)."""
        await _require_client().rename_secret(folder, item_name, new_name)
        return {"ok": True}

    @mcp_server.tool()
    async def list_folders() -> list[dict]:
        """List all folders."""
        return await _require_client().list_folders()

    @mcp_server.tool()
    async def rename_folder(folder: str, new_name: str) -> dict:
        """Rename a folder."""
        await _require_client().rename_folder(folder, new_name)
        return {"ok": True}

    @mcp_server.tool()
    async def empty_trash() -> dict:
        """Permanently delete all soft-deleted items in trash."""
        await _require_client().empty_trash()
        return {"ok": True}

    @mcp_server.tool()
    async def search_secrets(query: str) -> list[dict]:
        """Search secrets by name across all folders. Returns folder + item_name for each match."""
        return await _require_client().search_secrets(query)


# -- routes ----------------------------------------------------------------


def _register_routes(mcp_server: MCPServer) -> None:
    from .web import register_routes

    register_routes(mcp_server, _require_client)

    @mcp_server.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def health_route(request):
        del request
        return JSONResponse({"ok": True})


# -- transport security ----------------------------------------------------


def _build_transport_security() -> TransportSecuritySettings:
    return TransportSecuritySettings(enable_dns_rebinding_protection=False)


# -- main -----------------------------------------------------------------


def _build_app(mcp_server: MCPServer, config_path: str) -> object:
    inner = mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        host=os.environ.get("HOST", "127.0.0.1"),
        transport_security=_build_transport_security(),
    )
    sdk_lifespan = inner.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with _build_lifespan(config_path, http=True)(mcp_server):
            async with sdk_lifespan(app):
                yield

    inner.router.lifespan_context = lifespan
    return _IdentityMiddleware(inner)


def main() -> None:
    parser = argparse.ArgumentParser(prog="passage-mcp-server")
    parser.add_argument("--config", required=True, help="Path to config.json")
    parser.add_argument("--stdio", action="store_true", help="Run in stdio mode (default: HTTP+SSE)")
    args = parser.parse_args()

    _setup_logging()

    mcp = MCPServer(
        "passage",
        lifespan=_build_lifespan(args.config) if args.stdio else None,
        version="0.2.0",
        cache_hints={
            "server/discover": CacheHint(ttl_ms=300_000, scope="public"),
            "tools/list": CacheHint(ttl_ms=300_000, scope="private"),
        },
    )

    _register_tools(mcp)
    if not args.stdio:
        _register_routes(mcp)

    if args.stdio:
        try:
            mcp.run(transport="stdio")
        except SystemExit:
            raise
        except Exception as e:
            logging.getLogger(__name__).error("Server failed: %s", e)
            sys.exit(1)
        return

    app = _build_app(mcp, args.config)

    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "8000")),
        forwarded_allow_ips="*",
        proxy_headers=True,
    )


if __name__ == "__main__":
    main()
