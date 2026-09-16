"""age-encrypted secret store laid out as a passage/pass tree.

Layout (all paths relative to ``store_dir``)::

    .age-recipients          public keys every entry is encrypted to
    <folder>/<name>.age      one encrypted JSON record per secret
    .trash/<folder>/<name>.age   soft-deleted entries

Encryption and decryption are delegated to the ``age`` binary. This module
never touches key material beyond passing file paths to ``age``.

Record format (plaintext, JSON)::

    {"password": "<secret>", "username": "<optional>"}

Entries written by hand with ``passage insert`` are not JSON; their full
content is treated as the secret and the username is empty.

The store must have exactly one ``.age-recipients`` file, at the root. Move and
rename never re-encrypt, so per-directory recipient files are rejected at
startup.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from .config import Config

logger = logging.getLogger(__name__)

SUFFIX = ".age"
TRASH_DIR = ".trash"
RECIPIENTS_FILE = ".age-recipients"
MAX_NAME_LEN = 200


class StoreError(Exception):
    pass


class NotFoundError(StoreError):
    pass


class ForbiddenError(StoreError):
    pass


class ConflictError(StoreError):
    pass


class InvalidNameError(StoreError):
    pass


class InternalError(StoreError):
    pass


def _check_name(value: str, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidNameError(f"{what} must be a non-empty string")
    if len(value) > MAX_NAME_LEN:
        raise InvalidNameError(f"{what} is too long (max {MAX_NAME_LEN} chars)")
    if "/" in value or "\\" in value:
        raise InvalidNameError(f"{what} must not contain path separators: {value!r}")
    if value.startswith("."):
        raise InvalidNameError(f"{what} must not start with '.': {value!r}")
    if any(ord(c) < 32 or c == "\x7f" for c in value):
        raise InvalidNameError(f"{what} must not contain control characters")
    return value


def _parse_record(raw: bytes) -> dict:
    try:
        obj = json.loads(raw)
    except ValueError:
        obj = None
    if isinstance(obj, dict) and isinstance(obj.get("password"), str):
        username = obj.get("username")
        return {
            "password": obj["password"],
            "username": username if isinstance(username, str) else "",
        }
    # Not one of our records: a plain passage/pass entry. Whole content is the secret.
    return {"password": raw.decode("utf-8", errors="replace").rstrip("\n"), "username": ""}


class AgeStore:
    def __init__(self, config: Config):
        self._root: Path = config.store_dir
        self._identity: Path = config.identity_file
        self._recipients: Path = self._root / RECIPIENTS_FILE
        self._allowed: list[str] | None = config.allowed_folders
        self._lock = asyncio.Lock()

    # -- paths ---------------------------------------------------------------

    def _folder_dir(self, folder: str) -> Path:
        return self._root / _check_name(folder, "folder")

    def _item_path(self, folder: str, name: str) -> Path:
        return self._folder_dir(folder) / (_check_name(name, "item_name") + SUFFIX)

    def _trash_path(self, folder: str, name: str) -> Path:
        return (
            self._root
            / TRASH_DIR
            / _check_name(folder, "folder")
            / (_check_name(name, "item_name") + SUFFIX)
        )

    # -- access control ------------------------------------------------------

    def _check_allowed(self, folder: str) -> None:
        if self._allowed is not None and folder not in self._allowed:
            raise ForbiddenError(f"Folder not in allowed_folders: {folder}")

    def _require_folder(self, folder: str) -> Path:
        self._check_allowed(folder)
        d = self._folder_dir(folder)
        if not d.is_dir():
            raise NotFoundError(f"Folder not found: {folder}")
        return d

    def _existing(self, folder: str, name: str) -> Path:
        self._require_folder(folder)
        p = self._item_path(folder, name)
        if not p.is_file():
            raise NotFoundError(f"Item not found: {name}")
        return p

    # -- age -----------------------------------------------------------------

    @staticmethod
    async def _run(binary: str, *args: str, stdin: bytes | None = None) -> bytes:
        try:
            proc = await asyncio.create_subprocess_exec(
                binary,
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as e:
            raise InternalError(f"{binary} binary not found on PATH") from e
        out, err = await proc.communicate(stdin)
        if proc.returncode != 0:
            msg = err.decode(errors="replace").strip()
            raise InternalError(f"{binary} exited {proc.returncode}: {msg}")
        return out

    async def _decrypt(self, path: Path) -> dict:
        raw = await self._run("age", "-d", "-i", str(self._identity), str(path))
        return _parse_record(raw)

    async def _encrypt(self, path: Path, record: dict) -> None:
        payload = json.dumps(record, ensure_ascii=False).encode("utf-8")
        tmp = path.with_name(path.name + ".tmp")
        tmp.unlink(missing_ok=True)
        try:
            await self._run("age", "-e", "-R", str(self._recipients), "-o", str(tmp), stdin=payload)
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)

    # -- listing helpers -----------------------------------------------------

    def _iter_folders(self) -> list[str]:
        if not self._root.is_dir():
            return []
        return sorted(
            p.name for p in self._root.iterdir() if p.is_dir() and not p.name.startswith(".")
        )

    @staticmethod
    def _iter_items(folder_dir: Path) -> list[str]:
        if not folder_dir.is_dir():
            return []
        return sorted(
            p.name[: -len(SUFFIX)]
            for p in folder_dir.iterdir()
            if p.is_file() and p.name.endswith(SUFFIX) and not p.name.startswith(".")
        )

    # -- reads ---------------------------------------------------------------

    async def get_secret(self, folder: str, item_name: str) -> str:
        p = self._existing(folder, item_name)
        return (await self._decrypt(p))["password"]

    async def get_login(self, folder: str, item_name: str) -> dict:
        p = self._existing(folder, item_name)
        return await self._decrypt(p)

    async def list_secrets(self, folder: str | None = None) -> list[dict]:
        if folder is not None:
            if self._allowed is not None and folder not in self._allowed:
                return []
            try:
                d = self._folder_dir(folder)
            except InvalidNameError:
                return []
            items = self._iter_items(d)
            if not items:
                return []
            return [{"folder": folder, "items": [{"name": n} for n in items]}]

        result: list[dict] = []
        for f in self._iter_folders():
            if self._allowed is not None and f not in self._allowed:
                continue
            items = self._iter_items(self._root / f)
            if items:
                result.append({"folder": f, "items": [{"name": n} for n in items]})
        return result

    async def list_folders(self) -> list[dict]:
        return [{"name": f} for f in self._iter_folders()]

    async def search_secrets(self, query: str) -> list[dict]:
        q = query.strip().lower()
        if not q:
            return []
        results: list[dict] = []
        for f in self._iter_folders():
            if self._allowed is not None and f not in self._allowed:
                continue
            for name in self._iter_items(self._root / f):
                if q in name.lower():
                    results.append({"folder": f, "item_name": name})
        return results

    async def list_trash(self) -> list[dict]:
        trash = self._root / TRASH_DIR
        if not trash.is_dir():
            return []
        result: list[dict] = []
        for folder_dir in trash.iterdir():
            if not folder_dir.is_dir():
                continue
            for p in folder_dir.iterdir():
                if not (p.is_file() and p.name.endswith(SUFFIX)):
                    continue
                try:
                    mtime = p.stat().st_mtime
                except FileNotFoundError:
                    continue  # recovered or purged concurrently
                deleted = datetime.fromtimestamp(mtime, tz=timezone.utc)
                result.append({
                    "folder": folder_dir.name,
                    "name": p.name[: -len(SUFFIX)],
                    "deleted_date": deleted.isoformat(),
                })
        result.sort(key=lambda d: d["deleted_date"], reverse=True)
        return result

    # -- writes --------------------------------------------------------------

    async def _create(self, folder: str, item_name: str, record: dict) -> None:
        async with self._lock:
            self._require_folder(folder)
            p = self._item_path(folder, item_name)
            if p.exists():
                raise ConflictError(f"Item already exists: {item_name}")
            await self._encrypt(p, record)

    async def add_secret(self, folder: str, item_name: str, value: str) -> None:
        await self._create(folder, item_name, {"password": value, "username": ""})

    async def add_login(self, folder: str, item_name: str, username: str, password: str) -> None:
        await self._create(folder, item_name, {"password": password, "username": username})

    async def edit_secret(self, folder: str, item_name: str, value: str) -> None:
        async with self._lock:
            p = self._existing(folder, item_name)
            record = await self._decrypt(p)
            record["password"] = value
            await self._encrypt(p, record)

    async def delete_secret(self, folder: str, item_name: str) -> None:
        async with self._lock:
            p = self._existing(folder, item_name)
            t = self._trash_path(folder, item_name)
            t.parent.mkdir(parents=True, exist_ok=True)
            if t.exists():
                # keep the older trashed copy rather than overwrite it
                t.rename(t.with_name(f"{item_name}~{time.time_ns()}{SUFFIX}"))
            os.replace(p, t)
            os.utime(t)  # mtime = deletion time, shown by list_trash

    async def recover_secret(self, folder: str, item_name: str) -> None:
        async with self._lock:
            self._check_allowed(folder)
            t = self._trash_path(folder, item_name)
            if not t.is_file():
                raise NotFoundError(f"Item not in trash: {item_name}")
            d = self._folder_dir(folder)
            d.mkdir(exist_ok=True)
            p = d / (item_name + SUFFIX)
            if p.exists():
                raise ConflictError(f"Item already exists: {item_name}")
            os.replace(t, p)
            try:
                t.parent.rmdir()
            except OSError:
                pass

    async def empty_trash(self) -> None:
        async with self._lock:
            trash = self._root / TRASH_DIR
            if trash.is_dir():
                shutil.rmtree(trash)

    async def add_folder(self, folder: str) -> None:
        async with self._lock:
            d = self._folder_dir(folder)
            if d.exists():
                raise ConflictError(f"Folder already exists: {folder}")
            d.mkdir()
            if self._allowed is not None and folder not in self._allowed:
                self._allowed.append(folder)

    async def delete_folder(self, folder: str) -> None:
        async with self._lock:
            d = self._require_folder(folder)
            if any(d.iterdir()):
                raise ConflictError(f"Folder not empty: {folder}")
            d.rmdir()

    async def rename_folder(self, folder: str, new_name: str) -> None:
        async with self._lock:
            d = self._folder_dir(folder)
            if not d.is_dir():
                raise NotFoundError(f"Folder not found: {folder}")
            nd = self._folder_dir(new_name)
            if nd.exists():
                raise ConflictError(f"Folder already exists: {new_name}")
            old_trash = self._root / TRASH_DIR / folder
            new_trash = self._root / TRASH_DIR / new_name
            if old_trash.is_dir() and new_trash.exists():
                raise ConflictError(f"Trash already has a folder named {new_name}")
            d.rename(nd)
            if old_trash.is_dir():
                old_trash.rename(new_trash)
            if self._allowed is not None and folder in self._allowed:
                self._allowed[self._allowed.index(folder)] = new_name

    async def move_secret(self, folder: str, item_name: str, target_folder: str) -> None:
        async with self._lock:
            p = self._existing(folder, item_name)
            self._require_folder(target_folder)
            tp = self._item_path(target_folder, item_name)
            if tp.exists():
                raise ConflictError(f"Item already exists in {target_folder}: {item_name}")
            os.replace(p, tp)

    async def rename_secret(self, folder: str, item_name: str, new_name: str) -> None:
        async with self._lock:
            p = self._existing(folder, item_name)
            np = self._item_path(folder, new_name)
            if np.exists():
                raise ConflictError(f"Item already exists: {new_name}")
            os.replace(p, np)

    # -- startup -------------------------------------------------------------

    async def validate(self) -> None:
        if not self._root.is_dir():
            raise InternalError(f"Store directory missing: {self._root}")
        if not self._identity.is_file():
            raise InternalError(f"age identity file missing: {self._identity}")
        if not self._recipients.is_file():
            raise InternalError(f"Recipients file missing: {self._recipients}")

        nested = [p for p in self._root.rglob(RECIPIENTS_FILE) if p != self._recipients]
        if nested:
            raise InternalError(
                "Per-directory .age-recipients files are not supported "
                f"(move/rename never re-encrypt): {nested[0]}"
            )

        pubs = (await self._run("age-keygen", "-y", str(self._identity))).decode().split()
        recipients = [
            line.strip()
            for line in self._recipients.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if not any(pub in recipients for pub in pubs):
            raise InternalError(
                "The server identity's public key is not listed in .age-recipients; "
                "new writes would be unreadable by this server"
            )
        if len(recipients) < 2:
            logger.warning("Only one recipient configured: no recovery key. See README.")

        # Round trip proves the binary, identity, recipients, and write permission all work.
        probe = self._root / ".startup-probe.age"
        try:
            await self._encrypt(probe, {"password": "probe", "username": ""})
            if (await self._decrypt(probe))["password"] != "probe":
                raise InternalError("Startup probe decrypted to unexpected content")
        finally:
            probe.unlink(missing_ok=True)

        existing = self._iter_folders()
        for folder_name in self._allowed or []:
            if folder_name not in existing:
                logger.warning("Folder %r in allowed_folders not found in store", folder_name)
        if self._allowed is not None:
            for folder_name in existing:
                if folder_name not in self._allowed:
                    self._allowed.append(folder_name)
                    logger.info("Auto-allowed existing folder: %s", folder_name)

    async def close(self) -> None:
        pass
