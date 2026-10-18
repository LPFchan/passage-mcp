"""Private subject-keyed passage stores. Disk state is authoritative; no user cache.

Only the configured immutable owner subject uses the existing store. New vaults
use SHA-256 subject names and independent keys outside the ciphertext tree.
Provisioning is serialized across processes with flock, and committed by atomic
rename. A crash may leave an unused key or staging directory, never a replaced
identity. Service-owned private directories must not be writable by other users.
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import Config
from .store import AgeStore, InternalError


def safe_path(path: Path) -> Path:
    path = path.absolute()
    for component in (path, *path.parents):
        if component.is_symlink():
            raise InternalError('Symlinks are not supported in vault paths')
    return path


class TenantManager:
    def __init__(self, config: Config, owner: AgeStore):
        if not isinstance(config.legacy_owner_sub, str) or not config.legacy_owner_sub:
            raise InternalError('HTTP requires explicit legacy_owner_sub / LEGACY_OWNER_SUB')
        self.config = config
        self.owner = owner
        roots = [safe_path(p) for p in (config.store_dir, config.tenants_dir, config.tenant_keys_dir)]
        identity = safe_path(config.identity_file)
        if any(a == b or a in b.parents or b in a.parents for i, a in enumerate(roots) for b in roots[i + 1:]):
            raise InternalError('Legacy store, tenant stores, and tenant keys must be separate trees')
        if any(identity == root or root in identity.parents for root in roots):
            raise InternalError('Legacy identity must be outside vault and tenant trees')
        for root in roots[1:]:
            root.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(root, 0o700)
        self._locks = [asyncio.Lock() for _ in range(64)]

    def _provision(self, name: str) -> Config:
        root = safe_path(self.config.tenants_dir / name)
        key = safe_path(self.config.tenant_keys_dir / (name + '.key'))
        lockpath = safe_path(self.config.tenant_keys_dir / (name + '.lock'))
        fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            safe_path(root)
            safe_path(key)
            if root.exists():
                if not root.is_dir() or not key.is_file():
                    raise InternalError('Incomplete tenant vault; operator repair required')
                safe_path(root / '.age-recipients')
                if not (root / '.age-recipients').is_file():
                    raise InternalError('Tenant recipients missing; operator repair required')
            else:
                if not key.exists():
                    # age-keygen writes to stdout; capture, never log key material.
                    generated = subprocess.run(['age-keygen'], check=True, capture_output=True).stdout
                    keyfd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(keyfd, 'wb') as output:
                        output.write(generated)
                        output.flush()
                        os.fsync(output.fileno())
                pub = subprocess.run(['age-keygen', '-y', str(key)], check=True, capture_output=True).stdout
                stage = Path(tempfile.mkdtemp(prefix='.provision-', dir=self.config.tenants_dir))
                try:
                    recipients = stage / '.age-recipients'
                    recipients.write_bytes(pub)
                    recipients.chmod(0o600)
                    os.rename(stage, root)
                finally:
                    if stage.exists():
                        shutil.rmtree(stage)
        return Config(store_dir=root, identity_file=key)

    async def get_store(self, sub: str) -> AgeStore:
        if sub == self.config.legacy_owner_sub:
            return self.owner
        name = hashlib.sha256(sub.encode('utf-8')).hexdigest()
        lock = self._locks[int(name[:8], 16) % len(self._locks)]
        async with lock:
            config = await asyncio.to_thread(self._provision, name)
        store = AgeStore(config)
        store._lock = lock
        return store
