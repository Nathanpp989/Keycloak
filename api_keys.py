"""API-key issuance and verification for service clients.

An alternative to Bearer/OIDC for simple machine callers that just need a static
credential. Keys look like `ak_<id>_<secret>`; only the SHA-256 hash is stored
(the plaintext is returned ONCE at creation, never again). The id embedded in the
key gives an O(1) lookup, then the full key is compared constant-time against the
stored hash.

Storage is in-process by default — keys do NOT survive a restart (same as
registered users). For production, back the store with a persistent one (OpenBao
KV, a DB); the manager interface stays the same.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time

_PREFIX = "ak_"


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


class APIKeyManager:
    def __init__(self):
        self._store: dict[str, dict] = {}   # key_id -> {hash,name,created,revoked}
        self._lock = threading.Lock()

    def create(self, name: str = "") -> tuple[str, str]:
        """Create a key. Returns (key_id, plaintext_key). Plaintext shown ONCE."""
        key_id = secrets.token_hex(8)
        full = f"{_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
        with self._lock:
            self._store[key_id] = {"hash": _hash(full), "name": name,
                                   "created": time.time(), "revoked": False}
        return key_id, full

    def verify(self, key: str) -> dict | None:
        """Return {id,name,created} if the key is valid + not revoked, else None."""
        if not key or not key.startswith(_PREFIX):
            return None
        body = key[len(_PREFIX):]
        key_id = body.split("_", 1)[0] if "_" in body else ""
        if not key_id:
            return None
        h = _hash(key)
        with self._lock:
            rec = self._store.get(key_id)
            if rec and not rec["revoked"] and hmac.compare_digest(rec["hash"], h):
                return {"id": key_id, "name": rec["name"], "created": rec["created"]}
        return None

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            rec = self._store.get(key_id)
            if not rec or rec["revoked"]:
                return False
            rec["revoked"] = True
            return True

    def list_keys(self) -> list[dict]:
        with self._lock:
            return [{"id": kid, "name": r["name"], "created": r["created"],
                     "revoked": r["revoked"]} for kid, r in self._store.items()]


_MANAGER: APIKeyManager | None = None
_build_lock = threading.Lock()


def api_key_manager() -> APIKeyManager:
    global _MANAGER
    if _MANAGER is None:
        with _build_lock:
            if _MANAGER is None:
                _MANAGER = APIKeyManager()
    return _MANAGER


def reset_api_keys() -> None:
    """Test hook: rebuild the manager (drops all keys)."""
    global _MANAGER
    with _build_lock:
        _MANAGER = None
