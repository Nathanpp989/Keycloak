"""API-key issuance and verification for service clients.

An alternative to Bearer/OIDC for simple machine callers that just need a static
credential. Keys look like `ak_<id>_<secret>`; only the SHA-256 hash is stored
(the plaintext is returned ONCE at creation). The id embedded in the key gives an
O(1) lookup; the full key is then compared constant-time against the stored hash.

Storage is pluggable:
  - memory (default): in-process dict — does NOT survive a restart.
  - openbao (API_KEY_BACKEND=openbao): records persisted as JSON in OpenBao KV v2,
    so keys survive restarts AND are shared across replicas. Keys are secrets, so
    the secrets store is their natural home.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

_KEY_PREFIX = "ak_"          # prefix on the key string itself
_PATH_PREFIX = "api-keys/"   # KV path prefix for stored records


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


# ── storage backends ────────────────────────────────────────────────────────

class _MemoryStore:
    """In-process record store (default). Not shared, not persisted."""

    def __init__(self):
        self._d: dict[str, dict] = {}
        self._lock = threading.Lock()

    def get(self, kid: str) -> dict | None:
        with self._lock:
            rec = self._d.get(kid)
            return dict(rec) if rec else None

    def put(self, kid: str, rec: dict) -> None:
        with self._lock:
            self._d[kid] = dict(rec)

    def list_ids(self) -> list[str]:
        with self._lock:
            return list(self._d.keys())


class _OpenBaoStore:
    """Records persisted as JSON in OpenBao KV v2 at <mount>/data/api-keys/<id>.

    Survives restarts and is shared across replicas. Uses the same OpenBao auth
    (static token or AppRole) as the rest of the app.
    """

    def __init__(self, secrets_client=None):
        import openbao_connect as ob
        self._ob = ob
        self._secrets = secrets_client or ob.OpenBaoSecrets()

    def get(self, kid: str) -> dict | None:
        try:
            return json.loads(self._secrets.get_secret(_PATH_PREFIX + kid))
        except Exception:  # noqa: BLE001 - absent/unreachable -> no record
            return None

    def put(self, kid: str, rec: dict) -> None:
        self._secrets.put_secret(_PATH_PREFIX + kid, json.dumps(rec))

    def list_ids(self) -> list[str]:
        try:
            s = self._secrets
            resp = self._ob._request("LIST", f"{s.mount}/metadata/{_PATH_PREFIX}",
                                     token=s.token, addr=s.addr)
            data = self._ob._check(resp, "list api-keys")
            return list((data.get("data") or {}).get("keys") or [])
        except Exception:  # noqa: BLE001 - empty/absent path lists as nothing
            return []


def _make_store():
    if os.environ.get("API_KEY_BACKEND", "memory").strip().lower() == "openbao":
        return _OpenBaoStore()
    return _MemoryStore()


# ── manager ─────────────────────────────────────────────────────────────────

class APIKeyManager:
    def __init__(self, store=None):
        self._store = store if store is not None else _MemoryStore()
        self._lock = threading.Lock()   # serialize create/revoke within a process

    def create(self, name: str = "", ttl_seconds: int | None = None,
               scopes: list[str] | None = None) -> tuple[str, str]:
        """Create a key. Returns (key_id, plaintext_key). Plaintext shown ONCE.

        ttl_seconds: if set, the key expires that many seconds from now (None =
        never expires). scopes: optional list limiting what the key may do
        (enforced by require_api_key_scope); empty = no scope restriction.
        """
        key_id = secrets.token_hex(8)
        full = f"{_KEY_PREFIX}{key_id}_{secrets.token_urlsafe(32)}"
        now = time.time()
        with self._lock:
            self._store.put(key_id, {
                "hash": _hash(full), "name": name, "created": now,
                "revoked": False,
                "expires_at": (now + ttl_seconds) if (ttl_seconds and ttl_seconds > 0) else None,
                "scopes": list(scopes) if scopes else [],
            })
        return key_id, full

    def verify(self, key: str) -> dict | None:
        """Return {id,name,created,expires_at,scopes} if the key is valid — not
        revoked and not expired — else None."""
        if not key or not key.startswith(_KEY_PREFIX):
            return None
        body = key[len(_KEY_PREFIX):]
        key_id = body.split("_", 1)[0] if "_" in body else ""
        if not key_id:
            return None
        rec = self._store.get(key_id)
        if not rec or rec.get("revoked"):
            return None
        exp = rec.get("expires_at")
        if exp is not None and time.time() > exp:      # expired
            return None
        if not hmac.compare_digest(str(rec.get("hash", "")), _hash(key)):
            return None
        return {"id": key_id, "name": rec.get("name", ""),
                "created": rec.get("created"), "expires_at": exp,
                "scopes": list(rec.get("scopes") or [])}

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            rec = self._store.get(key_id)
            if not rec or rec.get("revoked"):
                return False
            rec["revoked"] = True
            self._store.put(key_id, rec)
            return True

    def list_keys(self) -> list[dict]:
        out = []
        for kid in self._store.list_ids():
            rec = self._store.get(kid)
            if rec:
                out.append({"id": kid, "name": rec.get("name", ""),
                            "created": rec.get("created"),
                            "expires_at": rec.get("expires_at"),
                            "scopes": list(rec.get("scopes") or []),
                            "revoked": bool(rec.get("revoked", False))})
        return out


_MANAGER: APIKeyManager | None = None
_build_lock = threading.Lock()


def api_key_manager() -> APIKeyManager:
    global _MANAGER
    if _MANAGER is None:
        with _build_lock:
            if _MANAGER is None:
                _MANAGER = APIKeyManager(_make_store())
    return _MANAGER


def reset_api_keys() -> None:
    """Test hook: rebuild the manager (drops all in-memory keys / re-reads env)."""
    global _MANAGER
    with _build_lock:
        _MANAGER = None
