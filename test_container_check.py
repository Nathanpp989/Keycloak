#!/usr/bin/env python3
"""Tests for container_check.py — the static container validator.

The critical property is that it CATCHES regressions, so most tests feed it
deliberately broken input. A validator that only ever passes is worthless."""
from __future__ import annotations

import os

import container_check as cc

GOOD_DOCKERFILE = """FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    HOST=0.0.0.0 \\
    PORT=8000 \\
    KEY_DIR=/data/keys
WORKDIR /app
COPY *.py ./
USER appuser
CMD ["python", "main.py"]
"""

BAD_COMMENT_IN_CONTINUATION = """FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    # App defaults
    HOST=0.0.0.0 \\
    KEY_DIR=/data/keys
USER appuser
"""


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_joiner_exposes_truncating_comment():
    instrs = cc._instructions_with_continuations(BAD_COMMENT_IN_CONTINUATION)
    env = next(i for i in instrs if i.startswith("ENV"))
    # The reality is worse than "the comment is included": the instruction ENDS
    # at the comment line (which has no trailing backslash), so HOST and
    # KEY_DIR are lost ENTIRELY. That is the silent failure this check exists
    # to prevent — container binds loopback, healthcheck still passes.
    assert "#" in env
    assert "HOST=0.0.0.0" not in env
    assert "KEY_DIR" not in env

def test_joiner_clean_file_keeps_all_vars():
    instrs = cc._instructions_with_continuations(GOOD_DOCKERFILE)
    env = next(i for i in instrs if i.startswith("ENV"))
    assert "#" not in env
    for v in ("HOST=0.0.0.0", "PORT=8000", "KEY_DIR=/data/keys"):
        assert v in env

def test_check_flags_comment_in_continuation(tmp_path):
    path = _write(tmp_path, "Dockerfile", BAD_COMMENT_IN_CONTINUATION)
    c = cc.Check()
    cc.check_dockerfile(path, c)
    assert any("comment inside a line continuation" in f for f in c.failed)

def test_check_flags_missing_host(tmp_path):
    path = _write(tmp_path, "Dockerfile",
                  "FROM x\nENV PORT=8000 \\\n    KEY_DIR=/d\nUSER u\n")
    c = cc.Check()
    cc.check_dockerfile(path, c)
    assert any("HOST is not set to 0.0.0.0" in f for f in c.failed)
    # and the message must explain the silent-failure consequence
    assert any("unreachable" in f and "healthcheck" in f for f in c.failed)

def test_check_flags_missing_key_dir(tmp_path):
    path = _write(tmp_path, "Dockerfile", "FROM x\nENV HOST=0.0.0.0\nUSER u\n")
    c = cc.Check()
    cc.check_dockerfile(path, c)
    assert any("KEY_DIR missing" in f for f in c.failed)

def test_check_warns_on_root_user(tmp_path):
    path = _write(tmp_path, "Dockerfile",
                  "FROM x\nENV HOST=0.0.0.0 \\\n    KEY_DIR=/d\n")
    c = cc.Check()
    cc.check_dockerfile(path, c)
    assert any("run as root" in w for w in c.warned)

def test_check_passes_clean_dockerfile(tmp_path):
    path = _write(tmp_path, "Dockerfile", GOOD_DOCKERFILE)
    c = cc.Check()
    cc.check_dockerfile(path, c)
    assert c.failed == []

def test_missing_dockerfile_is_a_failure():
    c = cc.Check()
    cc.check_dockerfile("/nonexistent/Dockerfile", c)
    assert any("missing" in f for f in c.failed)


# ── the real project must pass its own checks ───────────────────────────────
def test_real_project_passes_all_container_checks():
    here = os.path.dirname(os.path.abspath(__file__))
    cwd = os.getcwd()
    try:
        os.chdir(here)
        assert cc.run() == 0
    finally:
        os.chdir(cwd)


def test_flags_shipped_file_with_unmet_dep(tmp_path, monkeypatch):
    # A shipped .py importing a package not in requirements must be flagged —
    # this is the check that catches a dev tool (importing e.g. pyyaml) leaking
    # into the image.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n")
    (tmp_path / "main.py").write_text("import requests\n")
    (tmp_path / ".dockerignore").write_text("__pycache__/\n")
    # a shipped tool importing something NOT in requirements
    (tmp_path / "sometool.py").write_text("import yaml\n")
    c = cc.Check()
    cc.check_imports_shipped(c)
    assert any("sometool.py" in f and "yaml" in f for f in c.failed)

def test_shipped_file_excluded_is_not_flagged(tmp_path, monkeypatch):
    # Same tool, but excluded via .dockerignore -> not shipped -> no failure.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "requirements.txt").write_text("requests>=2.0\n")
    (tmp_path / "main.py").write_text("import requests\n")
    (tmp_path / ".dockerignore").write_text("__pycache__/\nsometool.py\n")
    (tmp_path / "sometool.py").write_text("import yaml\n")
    c = cc.Check()
    cc.check_imports_shipped(c)
    assert not any("sometool.py" in f for f in c.failed)


def test_monitoring_check_passes_for_real_project(tmp_path, monkeypatch):
    # The real project's monitoring config should pass check_monitoring.
    import container_check as cc
    c = cc.Check()
    cc.check_monitoring(c)
    # no failures about monitoring
    mon_fails = [f for f in c.failed if "monitoring" in f]
    assert not mon_fails, f"monitoring checks failed: {mon_fails}"

def test_monitoring_check_flags_missing_prometheus_target(tmp_path, monkeypatch):
    # A prometheus.yml that omits a service must be flagged.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(
        "services:\n  prometheus:\n    image: prom/prometheus\n  grafana:\n    image: grafana/grafana\n")
    mon = tmp_path / "monitoring"
    mon.mkdir()
    # prometheus.yml missing the 'keycloak' target
    (mon / "prometheus.yml").write_text(
        "scrape_configs:\n"
        "  - job_name: app\n    static_configs:\n      - targets: ['app:8000']\n"
        "  - job_name: traefik\n    static_configs:\n      - targets: ['traefik:8080']\n")
    import container_check as cc
    c = cc.Check()
    cc.check_monitoring(c)
    assert any("keycloak" in f for f in c.failed)


def test_monitoring_check_validates_alerting(tmp_path, monkeypatch):
    # When alertmanager is a service, the rules file and alertmanager config
    # must exist and Prometheus must reference both.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(
        "services:\n  prometheus:\n    image: p\n  grafana:\n    image: g\n"
        "  alertmanager:\n    image: a\n")
    mon = tmp_path / "monitoring"
    (mon / "grafana" / "provisioning" / "datasources").mkdir(parents=True)
    (mon / "grafana" / "provisioning" / "dashboards").mkdir(parents=True)
    (mon / "grafana" / "provisioning" / "datasources" / "prometheus.yml").write_text(
        "datasources:\n  - uid: prometheus\n")
    (mon / "grafana" / "provisioning" / "dashboards" / "provider.yml").write_text("x: 1\n")
    (mon / "prometheus.yml").write_text(
        "scrape_configs:\n"
        "  - job_name: app\n    static_configs:\n      - targets: ['app:8000']\n"
        "  - job_name: traefik\n    static_configs:\n      - targets: ['traefik:8080']\n"
        "  - job_name: keycloak\n    static_configs:\n      - targets: ['keycloak:9000']\n"
        "rule_files:\n  - /etc/prometheus/alert-rules.yml\n"
        "alerting:\n  alertmanagers:\n    - static_configs:\n        - targets: ['alertmanager:9093']\n")
    (mon / "alert-rules.yml").write_text("groups: []\n")
    (mon / "alertmanager.yml").write_text("route:\n  receiver: default\n")
    import container_check as cc
    c = cc.Check()
    cc.check_monitoring(c)
    mon_fails = [f for f in c.failed if "monitoring" in f]
    assert not mon_fails, f"unexpected failures: {mon_fails}"

def test_monitoring_check_flags_missing_alert_rules(tmp_path, monkeypatch):
    # alertmanager service but no rules file -> must be flagged.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "compose.yaml").write_text(
        "services:\n  prometheus:\n    image: p\n  alertmanager:\n    image: a\n")
    mon = tmp_path / "monitoring"
    mon.mkdir()
    (mon / "prometheus.yml").write_text(
        "scrape_configs:\n"
        "  - job_name: app\n    static_configs:\n      - targets: ['app:8000']\n"
        "  - job_name: traefik\n    static_configs:\n      - targets: ['traefik:8080']\n"
        "  - job_name: keycloak\n    static_configs:\n      - targets: ['keycloak:9000']\n")
    # no alert-rules.yml, no alertmanager.yml
    import container_check as cc
    c = cc.Check()
    cc.check_monitoring(c)
    assert any("alert-rules.yml missing" in f or "alert rules" in f.lower() for f in c.failed)
