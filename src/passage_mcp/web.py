"""Browser vault routes. Identity and request-scoped store are supplied by the host."""
from __future__ import annotations

import asyncio
import json

from starlette.responses import JSONResponse, RedirectResponse

from .identity import decode_subject, header_values
from .store import (ConflictError, ForbiddenError, InternalError, InvalidNameError,
                    NotFoundError, StoreError)

ORIGIN = "https://passage.lost.plus"
MAX_BODY = 131_072
HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
}
# Explicit HTTP surface: public operation names never select arbitrary store methods.
OPERATIONS = {
    "/api/folders/list": ("list_folders", ()),
    "/api/folders/create": ("add_folder", ("folder",)),
    "/api/folders/delete": ("delete_folder", ("folder",)),
    "/api/folders/rename": ("rename_folder", ("folder", "new_name")),
    "/api/secrets/list": ("list_secrets", ("folder",)),
    "/api/secrets/search": ("search_secrets", ("query",)),
    "/api/secrets/read": ("get_login", ("folder", "item_name")),
    "/api/secrets/create": ("add_secret", ("folder", "item_name", "value")),
    "/api/logins/create": ("add_login", ("folder", "item_name", "username", "password")),
    "/api/secrets/update": ("edit_secret", ("folder", "item_name", "value")),
    "/api/secrets/delete": ("delete_secret", ("folder", "item_name")),
    "/api/secrets/rename": ("rename_secret", ("folder", "item_name", "new_name")),
    "/api/secrets/move": ("move_secret", ("folder", "item_name", "target_folder")),
    "/api/trash/list": ("list_trash", ()),
    "/api/trash/recover": ("recover_secret", ("folder", "item_name")),
    "/api/trash/empty": ("empty_trash", ()),
}


def _json(data, status=200):
    return JSONResponse(data, status_code=status, headers=HEADERS)


def _identity(request):
    identity = request.scope.get("state", {}).get("passage_identity")
    if not isinstance(identity, dict) or not isinstance(identity.get("sub"), str) or not identity["sub"]:
        return None
    return {key: identity.get(key) for key in ("sub", "email", "name", "role")}


async def _payload(request):
    if request.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
        raise ValueError("Expected application/json")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY:
            raise OverflowError
    data = json.loads(body)
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return data


def register_routes(mcp_server, get_store):
    """Register once; get_store() must resolve the current authenticated request."""
    decrypt_slots = asyncio.Semaphore(4)

    async def masked_item(store, folder, item):
        async with decrypt_slots:
            try:
                record = await store.get_login(folder, item["name"])
            except NotFoundError:
                return None
            except InternalError:
                # age can lose the file after get_login's existence check.
                # Keep real decryption failures visible; skip only vanished names.
                current = await store.list_secrets(folder)
                if any(entry["name"] == item["name"] for group in current for entry in group["items"]):
                    raise
                return None
            value = record["password"]
            return {"name": item["name"], "masked": "••••" + (value[-4:] if len(value) > 4 else "")}

    @mcp_server.custom_route("/", methods=["GET"], include_in_schema=False)
    async def index(request):
        return RedirectResponse("https://auth.lost.plus/#passage", status_code=308, headers=HEADERS)

    @mcp_server.custom_route("/api/session", methods=["GET"], include_in_schema=False)
    async def session(request):
        identity = _identity(request)
        return _json(identity if identity else {"error": "Sign in required"}, 200 if identity else 401)

    def make_handler(method, fields):
        async def handle(request):
            identity = _identity(request)
            if identity is None:
                return _json({"error": "Sign in required"}, 401)
            headers = header_values(request.scope.get("headers", []))
            if decode_subject(headers.get("x-passage-subject")) != identity["sub"]:
                return _json({"error": "Account changed. Refresh the vault."}, 409)
            if request.headers.get("origin") != ORIGIN:
                return _json({"error": "Origin not allowed"}, 403)
            try:
                data = await _payload(request)
                if set(data) != set(fields) or any(not isinstance(data[k], str) for k in fields):
                    raise ValueError("Unexpected fields or field types")
                # The mapping and field lists above are the only allowed dispatch targets.
                store = get_store()
                result = await getattr(store, method)(**data)
                if method == "list_secrets":
                    for group in result:
                        masked = await asyncio.gather(*(masked_item(store, group["folder"], item)
                                                        for item in group["items"]))
                        group["items"] = [item for item in masked if item is not None]
                return _json({"data": result})
            except OverflowError:
                return _json({"error": "Request too large"}, 413)
            except (ValueError, UnicodeError, RecursionError):
                return _json({"error": "Invalid JSON request"}, 400)
            except StoreError as exc:
                status, message = 400, "Unable to complete operation"
                for cls, code, safe in (
                    (InternalError, 500, "Vault unavailable"),
                    (NotFoundError, 404, "Folder or item not found"),
                    (ForbiddenError, 403, "Access denied"),
                    (ConflictError, 409, "Name already exists or folder is not empty"),
                    (InvalidNameError, 400, "Invalid name: use 1–200 characters without path separators, leading dots or control characters"),
                ):
                    if isinstance(exc, cls):
                        status, message = code, safe
                        break
                return _json({"error": message}, status)
            except Exception:
                return _json({"error": "Vault unavailable"}, 500)
        return handle

    for path, (method, fields) in OPERATIONS.items():
        mcp_server.custom_route(path, methods=["POST"], include_in_schema=False)(make_handler(method, fields))
