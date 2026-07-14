from __future__ import annotations

import asyncio
import logging
import random
import time
import uuid
from typing import ClassVar
from dataclasses import dataclass

import httpx

from .config import Config

logger = logging.getLogger(__name__)

DEVICE_TYPE_SDK = 22

LOGIN_TYPE = 1
MCP_URI = "mcp-secret://"


class VaultwardenError(Exception):
    pass


class NotFoundError(VaultwardenError):
    pass


class ForbiddenError(VaultwardenError):
    pass


class DuplicateError(VaultwardenError):
    pass


class InternalError(VaultwardenError):
    pass


class ConflictError(VaultwardenError):
    pass


@dataclass(slots=True)
class _Folder:
    id: str
    name: str


@dataclass(slots=True)
class _SecretItem:
    name: str
    item_id: str
    password: str


class VaultwardenClient:
    _shared_http: ClassVar[httpx.AsyncClient | None] = None
    _shared_token: ClassVar[str | None] = None
    _shared_token_expiry: ClassVar[float] = 0
    _shared_device_id: ClassVar[str] = ""
    _token_lock: ClassVar[asyncio.Lock] = asyncio.Lock()

    def __init__(self, config: Config):
        self._url = config.vaultwarden_url
        self._client_id = config.client_id
        self._client_secret = config.client_secret
        self._allowed: list[str] | None = config.allowed_folders

        if not VaultwardenClient._shared_device_id:
            VaultwardenClient._shared_device_id = str(uuid.uuid4())

        self._folders: dict[str, _Folder] = {}
        self._folder_loaded = False

    async def _get_http(self) -> httpx.AsyncClient:
        if VaultwardenClient._shared_http is None:
            VaultwardenClient._shared_http = httpx.AsyncClient(timeout=httpx.Timeout(10.0))
        return VaultwardenClient._shared_http

    # -- auth ----------------------------------------------------------------

    async def _exchange_token(self) -> None:
        logger.info("Exchanging client credentials for access token")
        http = await self._get_http()
        try:
            resp = await http.post(
                f"{self._url}/identity/connect/token",
                content=(
                    f"grant_type=client_credentials"
                    f"&client_id={self._client_id}"
                    f"&client_secret={self._client_secret}"
                    f"&scope=api"
                    f"&device_identifier={VaultwardenClient._shared_device_id}"
                    f"&device_name=vaultwarden-mcp"
                    f"&device_type={DEVICE_TYPE_SDK}"
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            raise InternalError(f"Token exchange failed: {e}") from e

        VaultwardenClient._shared_token = data["access_token"]
        expires_in = data.get("expires_in", 7200)
        VaultwardenClient._shared_token_expiry = time.time() + expires_in
        logger.info("Token obtained, expires in %d seconds", expires_in)

    async def _access_token(self) -> str:
        if (
            VaultwardenClient._shared_token is not None
            and time.time() < VaultwardenClient._shared_token_expiry - 300
        ):
            return VaultwardenClient._shared_token

        async with VaultwardenClient._token_lock:
            if (
                VaultwardenClient._shared_token is not None
                and time.time() < VaultwardenClient._shared_token_expiry - 300
            ):
                return VaultwardenClient._shared_token

            for attempt in range(3):
                try:
                    await self._exchange_token()
                    return VaultwardenClient._shared_token
                except InternalError:
                    if attempt == 2:
                        raise
                    wait = (5 + random.uniform(0, 5)) * (2 ** attempt)
                    logger.warning("Token exchange attempt %d failed, retrying in %.1fs", attempt + 1, wait)
                    await asyncio.sleep(wait)
            raise InternalError("Token exchange failed after 3 attempts")

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    # -- folders -------------------------------------------------------------

    async def _load_folders(self) -> None:
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.get(
                f"{self._url}/api/folders",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
            body = resp.json()
            folder_list = body.get("data") or body.get("Data") or []
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to load folders: {e}") from e

        self._folders = {}
        for f in folder_list:
            fid = f.get("id") or f.get("Id")
            name = f.get("name") or f.get("Name") or ""
            if not name or not fid:
                continue
            if name not in self._folders:
                self._folders[name] = _Folder(id=fid, name=name)
        self._folder_loaded = True
        logger.info("Loaded %d folders", len(self._folders))

    async def _ensure_folders(self) -> None:
        if not self._folder_loaded:
            await self._load_folders()

    def _resolve_folder(self, folder_name: str) -> _Folder | None:
        return self._folders.get(folder_name)

    # -- ciphers / secrets ---------------------------------------------------

    async def _fetch_all_ciphers(self) -> list[dict]:
        token = await self._access_token()
        http = await self._get_http()
        all_items: list[dict] = []
        url = f"{self._url}/api/ciphers"

        while url:
            try:
                resp = await http.get(url, headers=self._auth_headers(token))
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as e:
                raise InternalError(f"Failed to fetch ciphers: {e}") from e

            all_items.extend(data.get("data") or data.get("Data") or [])
            url = data.get("continuationToken") or data.get("ContinuationToken")
            if url:
                if not url.startswith("http"):
                    url = f"{self._url}{url}"

        return all_items

    @staticmethod
    def _is_mcp_secret(item: dict) -> bool:
        if item.get("type") != LOGIN_TYPE:
            return False
        if not item.get("folderId"):
            return False
        login = item.get("login") or {}
        uris = login.get("uris") or []
        for u in uris:
            if u.get("uri") == MCP_URI:
                return True
        return False

    @staticmethod
    def _item_username(item: dict) -> str:
        login = item.get("login") or {}
        return login.get("username") or ""

    @staticmethod
    def _item_password(item: dict) -> str:
        login = item.get("login") or {}
        return login.get("password") or ""

    @staticmethod
    def _pick_one(matches: list[dict], *, prefer_trashed: bool = False) -> dict:
        """Disambiguate a list of ciphers with the same name.

        Default (``prefer_trashed=False``): prefer non-deleted (alive) items,
        picking the oldest by ``revisionDate`` (tie-break: ``creationDate``).
        When every candidate is trashed, fall back to the oldest trashed one.

        ``prefer_trashed=True`` (used by ``recover_secret``): prefer trashed
        items, falling back to the oldest alive one if none are trashed.
        """
        if not matches:
            raise ValueError("_pick_one requires at least one match")
        if prefer_trashed:
            primary = [m for m in matches if m.get("deletedDate")]
            fallback = [m for m in matches if not m.get("deletedDate")]
        else:
            primary = [m for m in matches if not m.get("deletedDate")]
            fallback = [m for m in matches if m.get("deletedDate")]
        pool = primary or fallback
        def _sort_key(m: dict) -> str:
            return m.get("revisionDate") or m.get("creationDate") or ""
        return min(pool, key=_sort_key)

    # -- tool operations -----------------------------------------------------

    async def _all_secrets(self) -> dict[str, list[_SecretItem]]:
        await self._ensure_folders()
        ciphers = await self._fetch_all_ciphers()

        folder_id_to_name: dict[str, str] = {}
        for f in self._folders.values():
            folder_id_to_name[f.id] = f.name

        result: dict[str, list[_SecretItem]] = {}
        for item in ciphers:
            if not self._is_mcp_secret(item):
                continue
            folder_id = item["folderId"]
            folder_name = folder_id_to_name.get(folder_id)
            if folder_name is None:
                continue
            if folder_name not in result:
                result[folder_name] = []
            result[folder_name].append(
                _SecretItem(
                    name=item["name"],
                    item_id=item["id"],
                    password=self._item_password(item),
                )
            )

        return result

    async def get_secret(
        self, folder: str, item_name: str, item_id: str | None = None
    ) -> str:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        matches: list[dict] = [
            c for c in ciphers
            if self._is_mcp_secret(c)
            and c.get("folderId") == f.id
            and c["name"] == item_name
        ]
        if not matches:
            raise NotFoundError(f"Item not found: {item_name}")

        chosen: dict
        if item_id is not None:
            by_id = [c for c in matches if c["id"] == item_id]
            if not by_id:
                raise NotFoundError(
                    f"Item not found: {item_name} (item_id={item_id})"
                )
            chosen = by_id[0]
        else:
            chosen = self._pick_one(matches)

        return self._item_password(chosen)

    async def get_login(
        self, folder: str, item_name: str, item_id: str | None = None
    ) -> dict:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        matches: list[dict] = [
            c for c in ciphers
            if self._is_mcp_secret(c)
            and c.get("folderId") == f.id
            and c["name"] == item_name
        ]
        if not matches:
            raise NotFoundError(f"Item not found: {item_name}")

        chosen: dict
        if item_id is not None:
            by_id = [c for c in matches if c["id"] == item_id]
            if not by_id:
                raise NotFoundError(
                    f"Item not found: {item_name} (item_id={item_id})"
                )
            chosen = by_id[0]
        else:
            chosen = self._pick_one(matches)

        return {
            "username": self._item_username(chosen),
            "password": self._item_password(chosen),
        }

    async def list_secrets(self, folder: str | None = None) -> list[dict]:
        """List available secrets in the given folder, or all folders if folder
        is None. The 'items' field contains a list of dicts (item_id, name,
        deleted) so callers can disambiguate duplicate names.

        Returns [] for unknown folders (consistent with prior behaviour).
        """
        if folder is not None:
            if self._allowed is not None and folder not in self._allowed:
                return []

            await self._ensure_folders()
            f = self._resolve_folder(folder)
            if f is None:
                return []

            ciphers = await self._fetch_all_ciphers()
            items: list[dict] = []
            for item in ciphers:
                if not self._is_mcp_secret(item):
                    continue
                if item.get("folderId") == f.id:
                    items.append({
                        "item_id": item["id"],
                        "name": item["name"],
                        "deleted": bool(item.get("deletedDate")),
                    })
            if not items:
                return []
            items.sort(key=lambda d: d["name"])
            return [{"folder": folder, "items": items}]

        secrets = await self._all_secrets()
        result: list[dict] = []
        for folder_name, items in sorted(secrets.items()):
            if self._allowed is not None and folder_name not in self._allowed:
                continue
            if not items:
                continue
            result.append({
                "folder": folder_name,
                "items": sorted(
                    {"item_id": i.item_id, "name": i.name}
                    for i in items
                ),
            })
        return result

    # -- mutations (write tools) ---------------------------------------------

    def _check_allowed(self, folder: str) -> None:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

    async def _require_folder(self, folder: str) -> _Folder:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")
        return f

    async def _find_item(
        self,
        folder_id: str,
        item_name: str,
        *,
        item_id: str | None = None,
        include_trashed: bool = False,
        prefer_trashed: bool = False,
    ) -> dict:
        """Find a cipher by folder+name (or by item_id for disambiguation).

        ``include_trashed`` controls whether soft-deleted ciphers are matched.
        For writes (edit/delete/rename/move) we exclude trashed (the prior
        behaviour). For ``recover_secret`` we prefer trashed.

        If ``item_id`` is given, we look it up directly and raise NotFoundError
        if the id doesn't exist in the matching name set. Otherwise we use
        ``_pick_one`` to disambiguate duplicates deterministically.
        """
        ciphers = await self._fetch_all_ciphers()
        candidates: list[dict] = []
        for c in ciphers:
            if c.get("folderId") != folder_id:
                continue
            if c["name"] != item_name:
                continue
            if not include_trashed and c.get("deletedDate"):
                continue
            candidates.append(c)
        if not candidates:
            raise NotFoundError(f"Item not found: {item_name}")
        if item_id is not None:
            for c in candidates:
                if c["id"] == item_id:
                    return c
            raise NotFoundError(f"Item not found: {item_name} (item_id={item_id})")
        return self._pick_one(candidates, prefer_trashed=prefer_trashed)

    async def add_secret(self, folder: str, item_name: str, value: str) -> None:
        f = await self._require_folder(folder)
        try:
            await self._find_item(f.id, item_name)
            raise ConflictError(f"Item already exists: {item_name}")
        except NotFoundError:
            pass

        token = await self._access_token()
        http = await self._get_http()
        payload = {
            "type": LOGIN_TYPE,
            "folderId": f.id,
            "name": item_name,
            "login": {
                "username": item_name.lower(),
                "password": value,
                "uris": [{"uri": MCP_URI, "match": None}],
            },
        }
        try:
            resp = await http.post(
                f"{self._url}/api/ciphers",
                headers=self._auth_headers(token),
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to create secret: {e}") from e

    async def add_login(self, folder: str, item_name: str, username: str, password: str) -> None:
        f = await self._require_folder(folder)
        try:
            await self._find_item(f.id, item_name)
            raise ConflictError(f"Item already exists: {item_name}")
        except NotFoundError:
            pass

        token = await self._access_token()
        http = await self._get_http()
        payload = {
            "type": LOGIN_TYPE,
            "folderId": f.id,
            "name": item_name,
            "login": {
                "username": username,
                "password": password,
                "uris": [{"uri": MCP_URI, "match": None}],
            },
        }
        try:
            resp = await http.post(
                f"{self._url}/api/ciphers",
                headers=self._auth_headers(token),
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to create login: {e}") from e

    async def edit_secret(
        self, folder: str, item_name: str, value: str, item_id: str | None = None
    ) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name, item_id=item_id)
        if not self._is_mcp_secret(item):
            raise NotFoundError(f"Item not an MCP secret: {item_name}")

        token = await self._access_token()
        http = await self._get_http()
        login = item.get("login") or {}
        login["password"] = value
        payload = {
            "type": item["type"],
            "folderId": item["folderId"],
            "name": item["name"],
            "login": login,
        }
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}",
                headers=self._auth_headers(token),
                json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to update secret: {e}") from e

    async def delete_secret(
        self, folder: str, item_name: str, item_id: str | None = None
    ) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name, item_id=item_id)
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}/delete",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to delete secret: {e}") from e

    async def recover_secret(
        self, folder: str, item_name: str, item_id: str | None = None
    ) -> None:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        # For recover we look at the trashed pool first (prefer_trashed=True)
        # but fall back to alive items if nothing is trashed — that matches
        # the prior behaviour of picking the (single) match without filter.
        candidates: list[dict] = []
        for c in ciphers:
            if c.get("folderId") == f.id and c["name"] == item_name:
                candidates.append(c)
        if not candidates:
            raise NotFoundError(f"Item not found: {item_name}")
        if item_id is not None:
            for c in candidates:
                if c["id"] == item_id:
                    chosen = c
                    break
            else:
                raise NotFoundError(f"Item not found: {item_name} (item_id={item_id})")
        else:
            chosen = self._pick_one(candidates, prefer_trashed=True)

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{chosen['id']}/restore",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to recover secret: {e}") from e

    async def add_folder(self, folder: str) -> None:
        await self._ensure_folders()
        if folder in self._folders:
            raise ConflictError(f"Folder already exists: {folder}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.post(
                f"{self._url}/api/folders",
                headers=self._auth_headers(token),
                json={"name": folder},
            )
            resp.raise_for_status()
            data = resp.json()
            fid = data.get("id") or data.get("Id")
            self._folders[folder] = _Folder(id=fid, name=folder)
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to create folder: {e}") from e

        if self._allowed is not None and folder not in self._allowed:
            self._allowed.append(folder)

    async def delete_folder(self, folder: str) -> None:
        self._check_allowed(folder)
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")

        ciphers = await self._fetch_all_ciphers()
        for c in ciphers:
            if c.get("folderId") == f.id and not c.get("deletedDate"):
                raise ConflictError(f"Folder not empty: {folder}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.delete(
                f"{self._url}/api/folders/{f.id}",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
            del self._folders[folder]
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to delete folder: {e}") from e

    async def list_folders(self) -> list[dict]:
        """List all folders with their IDs."""
        await self._ensure_folders()
        return [
            {"id": f.id, "name": f.name}
            for f in self._folders.values()
        ]

    async def rename_folder(self, folder: str, new_name: str) -> None:
        await self._ensure_folders()
        f = self._resolve_folder(folder)
        if f is None:
            raise NotFoundError(f"Folder not found: {folder}")
        if new_name in self._folders:
            raise ConflictError(f"Folder already exists: {new_name}")

        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.put(
                f"{self._url}/api/folders/{f.id}",
                headers=self._auth_headers(token),
                json={"name": new_name},
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to rename folder: {e}") from e

        old_allowed = self._allowed
        self._folders[new_name] = _Folder(id=f.id, name=new_name)
        del self._folders[folder]
        if old_allowed is not None and folder in old_allowed:
            old_allowed[old_allowed.index(folder)] = new_name

    async def move_secret(
        self,
        folder: str,
        item_name: str,
        target_folder: str,
        item_id: str | None = None,
    ) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name, item_id=item_id)
        if not self._is_mcp_secret(item):
            raise NotFoundError(f"Item not an MCP secret: {item_name}")
        tf = await self._require_folder(target_folder)
        token = await self._access_token()
        http = await self._get_http()
        login = item.get("login") or {}
        payload = {"type": item["type"], "folderId": tf.id, "name": item["name"], "login": login}
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}",
                headers=self._auth_headers(token), json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to move secret: {e}") from e

    async def rename_secret(
        self,
        folder: str,
        item_name: str,
        new_name: str,
        item_id: str | None = None,
    ) -> None:
        f = await self._require_folder(folder)
        item = await self._find_item(f.id, item_name, item_id=item_id)
        if not self._is_mcp_secret(item):
            raise NotFoundError(f"Item not an MCP secret: {item_name}")
        try:
            await self._find_item(f.id, new_name)
            raise ConflictError(f"Item already exists: {new_name}")
        except NotFoundError:
            pass
        token = await self._access_token()
        http = await self._get_http()
        login = item.get("login") or {}
        payload = {"type": item["type"], "folderId": item["folderId"], "name": new_name, "login": login}
        try:
            resp = await http.put(
                f"{self._url}/api/ciphers/{item['id']}",
                headers=self._auth_headers(token), json=payload,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Failed to rename secret: {e}") from e

    async def list_trash(self) -> list[dict]:
        """List MCP-tagged soft-deleted items (trash). Each entry has
        item_id, name, folder, and deleted_date (the original deletion ts
        from Vaultwarden, useful for the 30-day expiry).
        """
        await self._ensure_folders()
        ciphers = await self._fetch_all_ciphers()
        folder_ids = {f.id: f.name for f in self._folders.values()}
        result: list[dict] = []
        for c in ciphers:
            if not c.get("deletedDate"):
                continue
            if not self._is_mcp_secret(c):
                continue
            result.append({
                "item_id": c["id"],
                "name": c["name"],
                "folder": folder_ids.get(c.get("folderId", ""), c.get("folderId", "")),
                "deleted_date": c.get("deletedDate"),
            })
        # Newest first
        result.sort(key=lambda d: d.get("deleted_date") or "", reverse=True)
        return result

    async def empty_trash(self) -> None:
        await self._ensure_folders()
        ciphers = await self._fetch_all_ciphers()
        trashed_ids = [c["id"] for c in ciphers if c.get("deletedDate") and self._is_mcp_secret(c)]
        if not trashed_ids:
            return

        token = await self._access_token()
        http = await self._get_http()
        for cid in trashed_ids:
            try:
                resp = await http.delete(
                    f"{self._url}/api/ciphers/{cid}",
                    headers=self._auth_headers(token),
                )
                resp.raise_for_status()
            except httpx.HTTPError as e:
                raise InternalError(f"Failed to empty trash: {e}") from e

    # -- startup -------------------------------------------------------------

    async def validate(self) -> None:
        token = await self._access_token()
        http = await self._get_http()
        try:
            resp = await http.get(
                f"{self._url}/api/accounts/revision-date",
                headers=self._auth_headers(token),
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise InternalError(f"Vaultwarden unreachable: {e}") from e

        await self._load_folders()

        for folder_name in (self._allowed or []):
            if folder_name not in self._folders:
                logger.warning("Folder %r in allowed_folders not found in Vaultwarden", folder_name)

        if self._allowed is not None:
            for folder_name in self._folders:
                if folder_name not in self._allowed:
                    self._allowed.append(folder_name)
                    logger.info("Auto-allowed existing folder: %s", folder_name)

    async def search_secrets(self, query: str) -> list[dict]:
        q = query.strip().lower()
        if not q:
            return []

        secrets = await self._all_secrets()
        results: list[dict] = []
        for f_name, items in sorted(secrets.items()):
            if self._allowed is not None and f_name not in self._allowed:
                continue
            for item in items:
                if q in item.name.lower():
                    results.append({"folder": f_name, "item_name": item.name})
        return results

    async def close(self) -> None:
        pass
