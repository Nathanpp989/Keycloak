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
