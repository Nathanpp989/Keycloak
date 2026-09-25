"""Unit tests for api_keys.APIKeyManager."""
from api_keys import APIKeyManager


def test_create_and_verify():
    m = APIKeyManager()
    kid, key = m.create("svc")
    assert key.startswith("ak_")
    meta = m.verify(key)
    assert meta and meta["id"] == kid and meta["name"] == "svc"


def test_wrong_or_malformed_key_rejected():
    m = APIKeyManager()
    m.create("x")
    assert m.verify("ak_deadbeef_nope") is None
    assert m.verify("") is None
    assert m.verify("notaprefix") is None


def test_revoke():
    m = APIKeyManager()
    kid, key = m.create()
    assert m.verify(key) is not None
    assert m.revoke(kid) is True
    assert m.verify(key) is None
    assert m.revoke(kid) is False       # already revoked
    assert m.revoke("unknown") is False


def test_list_hides_secrets():
    m = APIKeyManager()
    m.create("a")
    rows = m.list_keys()
    assert rows and "hash" not in rows[0] and "api_key" not in rows[0]


import json
import re
import responses


@responses.activate
def test_openbao_backed_store_full_roundtrip():
    """API keys persisted through OpenBao KV v2: create -> verify -> list ->
    revoke all round-trip through the (mocked) OpenBao HTTP API, with the record
    stored as JSON. Proves the persistence backend works end to end."""
    import openbao_connect as ob
    from api_keys import APIKeyManager, _OpenBaoStore

    ADDR = "http://bao:8200"
    kv: dict[str, str] = {}   # simulates OpenBao KV: key_id -> stored JSON value

    def put_cb(request):
        kid = request.url.rsplit("/", 1)[1]
        kv[kid] = json.loads(request.body)["data"]["value"]
        return (200, {}, json.dumps({"data": {}}))

    def get_cb(request):
        kid = request.url.rsplit("/", 1)[1]
        if kid not in kv:
            return (404, {}, json.dumps({"errors": ["not found"]}))
        return (200, {}, json.dumps({"data": {"data": {"value": kv[kid]}}}))

    def list_cb(request):
        return (200, {}, json.dumps({"data": {"keys": list(kv.keys())}}))

    responses.add_callback(
        responses.POST, re.compile(rf"{ADDR}/v1/secret/data/api-keys/.*"),
        callback=put_cb)
    responses.add_callback(
        responses.GET, re.compile(rf"{ADDR}/v1/secret/data/api-keys/.*"),
        callback=get_cb)
    responses.add_callback(
        "LIST", f"{ADDR}/v1/secret/metadata/api-keys/", callback=list_cb)

    store = _OpenBaoStore(ob.OpenBaoSecrets(addr=ADDR, token="root"))
    m = APIKeyManager(store)

    kid, key = m.create("persisted-svc")
    assert kid in kv                       # written to (mocked) OpenBao
    meta = m.verify(key)                    # read back + hash-verified
    assert meta and meta["id"] == kid and meta["name"] == "persisted-svc"
    assert kid in [k["id"] for k in m.list_keys()]
    assert m.revoke(kid) is True
    assert m.verify(key) is None           # revocation persisted (revoked=true)


def test_api_key_expiration():
    import time as t
    import unittest.mock
    from api_keys import APIKeyManager
    m = APIKeyManager()
    _, key = m.create("svc", ttl_seconds=1000)
    assert m.verify(key) is not None                      # valid now
    with unittest.mock.patch("api_keys.time.time", return_value=t.time() + 2000):
        assert m.verify(key) is None                      # expired
    _, perm = m.create("perm")                            # no ttl -> never expires
    with unittest.mock.patch("api_keys.time.time", return_value=t.time() + 10**9):
        assert m.verify(perm) is not None


def test_api_key_scopes_carried():
    from api_keys import APIKeyManager
    m = APIKeyManager()
    _, key = m.create("svc", scopes=["read", "write"])
    meta = m.verify(key)
    assert set(meta["scopes"]) == {"read", "write"}
    assert meta["expires_at"] is None
