#!/usr/bin/env python3
# logging_config.py
# Structured (JSON) logging for the broker.
#
# Why: plain-text logs are hard to search, filter, and aggregate. Emitting one
# JSON object per line makes every log line machine-parseable — greppable by
# field today (`docker compose logs app | jq 'select(.level=="ERROR")'`) and
# ready for a log aggregator (Loki, ELK, CloudWatch) later, with no app changes.
#
# Design:
#   - Format is toggleable via LOG_FORMAT=json|text (default: json). Local dev
#     can set LOG_FORMAT=text for human-readable output; containers get JSON.
#   - Level via LOG_LEVEL (default INFO), unchanged from before.
#   - Pure stdlib — no python-json-logger dependency, keeping the image lean.
#   - Every existing logger.*(...) call keeps working untouched: this only
#     changes the OUTPUT format on the root handler, not the call sites.
#   - Structured extras: any `logger.info("msg", extra={"user": "x"})` fields
#     are merged into the JSON object. Exceptions include the traceback.

from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import os
import sys

# Holds the current request's correlation ID. contextvars is the right tool:
# it's async-safe (each request/task sees its own value) and readable from
# anywhere — including inside the log formatter — without threading the ID
# through every function signature. Empty string when outside a request.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "request_id", default="")

# Standard LogRecord attributes we DON'T want to duplicate into the JSON body
# (they're either already emitted as top-level fields or are internal noise).
_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "module", "msecs",
    "message", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "thread", "threadName", "taskName",
}


class JSONFormatter(logging.Formatter):
    """Format a LogRecord as a single-line JSON object.

    Output keys: timestamp (ISO-8601 UTC), level, logger, message, plus any
    structured `extra=` fields, plus `exception` (formatted traceback) when the
    record carries exc_info. Field order is stable for readability.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Base fields, in a deliberately stable, readable order.
        payload: dict = {
            "timestamp": _dt.datetime.fromtimestamp(
                record.created, tz=_dt.timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Inject the current request's correlation ID, if we're inside a request.
        # This is what lets you filter every log line for one request across the
        # whole app: `... | jq 'select(.request_id=="abc123")'`.
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid

        # Merge any structured extras passed via logger.*(..., extra={...}).
        # These are set as attributes on the record, so we pick up anything that
        # isn't a standard LogRecord attribute.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = _safe(value)

        # Attach exception info (traceback) if present.
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        # default=str so anything non-serializable degrades gracefully rather
        # than raising inside the logger (a logging call must never crash the app).
        return json.dumps(payload, default=str, ensure_ascii=False)


def _safe(value):
    """Best-effort make a value JSON-friendly without raising."""
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


def configure_logging() -> None:
    """Install the chosen formatter on the root logger.

    Reads LOG_FORMAT (json|text, default json) and LOG_LEVEL (default INFO).
    Idempotent: replaces existing handlers so repeated calls (e.g. in tests or
    reload) don't stack duplicate output.
    """
    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    fmt = os.environ.get("LOG_FORMAT", "json").lower()

    handler = logging.StreamHandler(sys.stdout)
    if fmt == "text":
        # Human-readable, matches the previous format for local dev parity.
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s — %(message)s"
        ))
    else:
        handler.setFormatter(JSONFormatter())

    root = logging.getLogger()
    root.setLevel(level)
    # Replace any existing handlers so we don't double-log (basicConfig or a
    # previous configure_logging call may have installed one).
    root.handlers[:] = [handler]

    # Route UNCAUGHT exceptions through the logger too, so a genuine crash is
    # emitted in the same (JSON) format as everything else instead of a raw
    # plain-text traceback from Python's default excepthook. Without this, an
    # unhandled exception would be the one thing in your logs that ISN'T
    # structured — exactly when structure matters most (a crash).
    _install_excepthook()


def _install_excepthook() -> None:
    """Send uncaught exceptions to the root logger.

    KeyboardInterrupt is deliberately left to the default handler: Ctrl+C is a
    clean, intentional shutdown, not a crash, and logging it as an error would
    be misleading (and could swallow the normal interrupt behaviour).
    """
    def handle(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logging.getLogger("uncaught").critical(
            "Uncaught exception", exc_info=(exc_type, exc_value, exc_tb))

    sys.excepthook = handle

def get_logger(name: str | None = None) -> logging.Logger:
    """Return a logger with the given name, or the root logger if None."""
    return logging.getLogger(name)
