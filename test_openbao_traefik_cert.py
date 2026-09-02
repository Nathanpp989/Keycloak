#!/usr/bin/env python3
"""Tests for openbao_traefik_cert.py — the Level 2 file-writing that turns an
OpenBao-issued cert into files Traefik serves. The OpenBao HTTP calls are
covered in test_openbao.py; here we test the local file/config generation with
real (temp) file I/O."""
from __future__ import annotations

import os
import stat
import tempfile

import yaml

import openbao_traefik_cert as tc


_CERT_DATA = {
    "certificate": "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
    "private_key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
    "issuing_ca": "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
}


def test_write_cert_files_creates_chain_and_locks_key():
    with tempfile.TemporaryDirectory() as d:
        cert_path, key_path = tc.write_cert_files(_CERT_DATA, d)
        assert os.path.exists(cert_path) and os.path.exists(key_path)
        # cert file must contain BOTH the leaf and the issuing CA (full chain)
        with open(cert_path) as f:
            chain = f.read()
        assert "LEAF" in chain and "CA" in chain
        assert chain.count("BEGIN CERTIFICATE") == 2
        # key file must be 0600
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600, oct(mode)


def test_write_cert_files_without_issuing_ca():
    # If no issuing_ca is present, the cert file is just the leaf (no crash).
    data = dict(_CERT_DATA)
    del data["issuing_ca"]
    with tempfile.TemporaryDirectory() as d:
        cert_path, _ = tc.write_cert_files(data, d)
        with open(cert_path) as f:
            assert f.read().count("BEGIN CERTIFICATE") == 1


def test_write_traefik_tls_config_is_valid_yaml_with_default_store():
    with tempfile.TemporaryDirectory() as d:
        cfg = tc.write_traefik_tls_config(
            d, "/etc/traefik/dynamic/c.pem", "/etc/traefik/dynamic/k.pem")
        with open(cfg) as f:
            parsed = yaml.safe_load(f)
        # must set the DEFAULT certificate (so TLS routers pick it up)
        dc = parsed["tls"]["stores"]["default"]["defaultCertificate"]
        assert dc["certFile"] == "/etc/traefik/dynamic/c.pem"
        assert dc["keyFile"] == "/etc/traefik/dynamic/k.pem"
        # and list it under certificates
        assert parsed["tls"]["certificates"][0]["certFile"].endswith("c.pem")


def test_write_traefik_config_uses_container_paths_not_host():
    # The config must reference the path Traefik sees inside its container,
    # which is what we pass in — not wherever the files happen to live on host.
    with tempfile.TemporaryDirectory() as d:
        cfg = tc.write_traefik_tls_config(
            d, "/etc/traefik/dynamic/openbao-cert.pem",
            "/etc/traefik/dynamic/openbao-key.pem")
        with open(cfg) as f:
            content = f.read()
        assert "/etc/traefik/dynamic/openbao-cert.pem" in content
        assert d not in content  # host temp path must NOT leak into the config


# ── Level 3: renewal logic ──────────────────────────────────────────────────
def _make_cert(ttl_seconds):
    """Build a real self-signed leaf cert with a given remaining lifetime.
    ttl_seconds may be negative to produce an already-expired cert."""
    from datetime import datetime, timezone, timedelta
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(seconds=ttl_seconds)
    # not_before must precede not_after; back it up well before both.
    not_before = min(now, not_after) - timedelta(days=1)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "app.localhost")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_cert_needs_renewal_missing_file():
    assert tc.cert_needs_renewal("/nonexistent/cert.pem") is True


def test_cert_needs_renewal_unparseable():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.pem")
        open(p, "w").write("not a cert")
        assert tc.cert_needs_renewal(p) is True


def test_cert_needs_renewal_fresh_long_cert():
    # A cert with ~365 days left is nowhere near due.
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.pem")
        open(p, "w").write(_make_cert(365 * 86400))
        assert tc.cert_needs_renewal(p) is False


def test_cert_needs_renewal_below_min_days():
    # A cert with only ~2 days left is due (under the 7-day floor).
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.pem")
        open(p, "w").write(_make_cert(2 * 86400))
        assert tc.cert_needs_renewal(p) is True


def test_cert_needs_renewal_expired():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c.pem")
        open(p, "w").write(_make_cert(-10))  # already expired
        assert tc.cert_needs_renewal(p) is True


def test_renew_if_needed_skips_when_not_due():
    from unittest.mock import patch
    import openbao_connect as ob
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "openbao-cert.pem"), "w").write(
            _make_cert(365 * 86400))
        with patch.object(ob, "issue_certificate") as iss:
            res = tc.renew_if_needed("traefik", ["app.localhost"], d)
        assert res["renewed"] is False
        iss.assert_not_called()  # must NOT re-issue when not due


def test_renew_failure_preserves_existing_cert():
    # THE safety property: if issuance fails, the existing cert is untouched.
    from unittest.mock import patch
    import openbao_connect as ob
    with tempfile.TemporaryDirectory() as d:
        cert_p = os.path.join(d, "openbao-cert.pem")
        original = _make_cert(60)  # short => due
        open(cert_p, "w").write(original)
        with patch.object(ob, "issue_certificate",
                        side_effect=ob.OpenBaoError("down")):
            try:
                tc.renew_if_needed("traefik", ["app.localhost"], d, force=True)
            except ob.OpenBaoError:
                pass
        assert open(cert_p).read() == original  # unchanged
