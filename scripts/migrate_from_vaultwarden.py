"""One-shot migration: Vaultwarden sqlite (plaintext MCP items) -> age store.

Run on the host with the repo venv. Never prints secret values.

    .venv/bin/python scripts/migrate_from_vaultwarden.py \
        --db vw-data/db.sqlite3 \
        --store /var/lib/vaultwarden-mcp/store \
        --identity /etc/vaultwarden-mcp/age-identity
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vaultwarden_mcp.config import Config  # noqa: E402
from vaultwarden_mcp.store import SUFFIX, TRASH_DIR, AgeStore  # noqa: E402


def load_items(db: Path) -> list[dict]:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    folders = {r[0]: r[1] for r in con.execute("select uuid, name from folders")}
    rows = con.execute(
        "select c.name, c.data, c.deleted_at, fc.folder_uuid "
        "from ciphers c left join folders_ciphers fc on fc.cipher_uuid = c.uuid"
    ).fetchall()
    items = []
    for name, data, deleted, folder_uuid in rows:
        if not folder_uuid:
            print(f"skip (no folder): {name}")
            continue
        d = json.loads(data)
        items.append({
            "folder": folders[folder_uuid],
            "name": name,
            "password": d.get("password") or "",
            "username": d.get("username") or "",
            "trashed": bool(deleted),
        })
    return items


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, type=Path)
    ap.add_argument("--store", required=True, type=Path)
    ap.add_argument("--identity", required=True, type=Path)
    ap.add_argument("--force", action="store_true", help="overwrite existing entries")
    args = ap.parse_args()

    store = AgeStore(Config(store_dir=args.store, identity_file=args.identity, allowed_folders=None))
    await store.validate()

    items = load_items(args.db)
    seen: set[tuple[str, str, bool]] = set()
    written = skipped = 0
    for it in items:
        key = (it["folder"], it["name"], it["trashed"])
        if key in seen:
            print(f"DUPLICATE in source, skipping second copy: {it['folder']}/{it['name']}")
            continue
        seen.add(key)
        base = args.store / TRASH_DIR if it["trashed"] else args.store
        path = base / it["folder"] / (it["name"] + SUFFIX)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and not args.force:
            skipped += 1
            continue
        await store._encrypt(path, {"password": it["password"], "username": it["username"]})
        written += 1

    # verify every source item reads back identically
    mismatches = 0
    for it in items:
        base = args.store / TRASH_DIR if it["trashed"] else args.store
        path = base / it["folder"] / (it["name"] + SUFFIX)
        rec = await store._decrypt(path)
        if rec["password"] != it["password"] or rec["username"] != it["username"]:
            mismatches += 1
            print(f"MISMATCH: {it['folder']}/{it['name']}")

    print(f"source items: {len(items)}  written: {written}  skipped(existing): {skipped}  mismatches: {mismatches}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
