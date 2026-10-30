"""Regression guard: local HS256 token verification must fail CLOSED when
SECRET_KEY is unset or left as the shipped placeholder.

Before the fix, verify_token defaulted the secret to the public literal
"change-me-in-production", so an unset SECRET_KEY let anyone forge a valid
token. These tests pin the fail-closed behaviour and confirm legitimate
operation still works once a real key is set.

The secret is read at CALL time (_local_token_secret reads os.getenv), so these
tests only set the env var — they never reload the module, which would swap out
the authorize.* callables that main.app wired its routes to and break the
/secure-data and /auth0/whoami dependency-override tests.
"""
import pytest
from fastapi import HTTPException
from jose import jwt

import authorize

_REAL = "a-strong-unique-signing-key"
_PLACEHOLDER = "change-me-in-production"


@pytest.mark.parametrize("secret", [None, "", _PLACEHOLDER])
def test_unset_or_placeholder_secret_fails_closed(monkeypatch, secret):
    if secret is None:
        monkeypatch.delenv("SECRET_KEY", raising=False)
    else:
        monkeypatch.setenv("SECRET_KEY", secret)
    # a token forged with the public placeholder must NOT be accepted
    forged = jwt.encode({"sub": "attacker"}, _PLACEHOLDER, algorithm="HS256")
    with pytest.raises(HTTPException) as ei:
        authorize.verify_token(forged)
    assert ei.value.status_code == 503          # misconfig, not a client 401
    assert "not configured" in ei.value.detail.lower()


def test_real_secret_accepts_its_own_token_and_rejects_placeholder(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", _REAL)
    good = jwt.encode({"sub": "alice"}, _REAL, algorithm="HS256")
    assert authorize.verify_token(good).username == "alice"
    # a token signed with the old placeholder is now just an invalid signature
    placeholder = jwt.encode({"sub": "attacker"}, _PLACEHOLDER, algorithm="HS256")
    with pytest.raises(HTTPException) as ei:
        authorize.verify_token(placeholder)
    assert ei.value.status_code == 401


def test_real_secret_still_requires_sub_claim(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", _REAL)
    no_sub = jwt.encode({"foo": "bar"}, _REAL, algorithm="HS256")
    with pytest.raises(HTTPException) as ei:
        authorize.verify_token(no_sub)
    assert ei.value.status_code == 401
