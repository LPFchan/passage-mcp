from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# Defaults match passage's own, so a laptop with an existing passage setup
# works in stdio mode with no config at all.
DEFAULT_STORE_DIR = "~/.passage/store"
DEFAULT_IDENTITY_FILE = "~/.passage/identities"


def _expand(value: str) -> Path:
    return Path(os.path.expanduser(os.path.expandvars(value)))


@dataclass(slots=True)
class Config:
    store_dir: Path
    identity_file: Path
    allowed_folders: list[str] | None = None

    @classmethod
    def from_path(cls, path: str) -> Config:
        expanded = _expand(path)
        data: dict = {}
        if expanded.exists():
            try:
                data = json.loads(expanded.read_text())
            except (OSError, json.JSONDecodeError) as e:
                raise SystemExit(f"Cannot read config: {e}")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> Config:
        store_dir = os.environ.get("SECRETS_STORE_DIR") or str(
            data.get("store_dir") or DEFAULT_STORE_DIR
        )
        identity_file = os.environ.get("AGE_IDENTITY_FILE") or str(
            data.get("identity_file") or DEFAULT_IDENTITY_FILE
        )

        allowed = data.get("allowed_folders")
        if allowed is not None:
            if not isinstance(allowed, list) or not all(isinstance(f, str) for f in allowed):
                raise SystemExit("allowed_folders must be a list of strings")

        return cls(
            store_dir=_expand(store_dir),
            identity_file=_expand(identity_file),
            allowed_folders=allowed,
        )
