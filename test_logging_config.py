# Tests for structured JSON logging configuration.
import json
import logging
import io

import logging_config


def _capture(fmt: str, monkeypatch) -> io.StringIO:
    """Configure logging with a captured stream and return it."""
    monkeypatch.setenv("LOG_FORMAT", fmt)
    monkeypatch.setenv("LOG_LEVEL", "INFO")
    logging_config.configure_logging()
    # Redirect the handler's stream to a buffer we can read.
    buf = io.StringIO()
    root = logging.getLogger()
    root.handlers[0].stream = buf
    return buf


def test_json_format_emits_valid_json(monkeypatch):
    buf = _capture("json", monkeypatch)
    logging.getLogger("t").info("hello")
    line = buf.getvalue().strip()
    obj = json.loads(line)  # must be parseable
    assert obj["message"] == "hello"
    assert obj["level"] == "INFO"
    assert obj["logger"] == "t"
    assert "timestamp" in obj


def test_json_includes_structured_extras(monkeypatch):
    buf = _capture("json", monkeypatch)
    logging.getLogger("t").info("msg", extra={"user": "alice", "rid": "x1"})
    obj = json.loads(buf.getvalue().strip())
    assert obj["user"] == "alice"
    assert obj["rid"] == "x1"


def test_json_captures_exception_traceback(monkeypatch):
    buf = _capture("json", monkeypatch)
    try:
        raise ValueError("boom")
    except ValueError:
        logging.getLogger("t").error("failed", exc_info=True)
    obj = json.loads(buf.getvalue().strip())
    assert "exception" in obj
    assert "ValueError: boom" in obj["exception"]


def test_json_handles_non_serializable_extra(monkeypatch):
    # A logging call must never crash the app, even with a weird extra value.
    buf = _capture("json", monkeypatch)
    logging.getLogger("t").info("msg", extra={"obj": object()})
    obj = json.loads(buf.getvalue().strip())  # still valid JSON
    assert "obj" in obj  # coerced to str, not dropped


def test_text_format_is_human_readable(monkeypatch):
    buf = _capture("text", monkeypatch)
    logging.getLogger("t").info("hello")
    line = buf.getvalue().strip()
    # text mode is NOT json
    assert "hello" in line
    assert "INFO" in line
    try:
        json.loads(line)
        assert False, "text mode should not be JSON"
    except json.JSONDecodeError:
        pass  # expected


def test_configure_is_idempotent_no_duplicate_handlers(monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "json")
    logging_config.configure_logging()
    logging_config.configure_logging()
    logging_config.configure_logging()
    # Repeated calls must not stack handlers (which would duplicate every line).
    assert len(logging.getLogger().handlers) == 1


def test_default_format_is_json(monkeypatch):
    # No LOG_FORMAT set -> defaults to json (the production-friendly default).
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    buf = _capture_default(monkeypatch)
    logging.getLogger("t").info("hi")
    json.loads(buf.getvalue().strip())  # parseable => json default


def _capture_default(monkeypatch) -> io.StringIO:
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    logging_config.configure_logging()
    buf = io.StringIO()
    logging.getLogger().handlers[0].stream = buf
    return buf


def test_excepthook_logs_uncaught_as_json(monkeypatch):
    import sys
    buf = _capture("json", monkeypatch)
    logging_config._install_excepthook()
    # simulate an uncaught exception reaching the hook
    try:
        raise RuntimeError("crash!")
    except RuntimeError:
        sys.excepthook(*sys.exc_info())
    obj = json.loads(buf.getvalue().strip())
    assert obj["level"] == "CRITICAL"
    assert "exception" in obj
    assert "RuntimeError: crash!" in obj["exception"]


def test_excepthook_leaves_keyboardinterrupt_to_default(monkeypatch):
    import sys
    buf = _capture("json", monkeypatch)
    logging_config._install_excepthook()
    called = {"default": False}
    orig = sys.__excepthook__
    monkeypatch.setattr(sys, "__excepthook__",
                        lambda *a: called.__setitem__("default", True))
    try:
        sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)
    finally:
        sys.__excepthook__ = orig
    # KeyboardInterrupt must go to the default handler, NOT be logged
    assert called["default"] is True
    assert buf.getvalue().strip() == ""   # nothing logged
