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