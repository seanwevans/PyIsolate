"""Logging helpers for PyIsolate."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

_BASE_RECORD_FIELDS = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
    "message",
}


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
            "event": getattr(record, "event", "log"),
        }
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in _BASE_RECORD_FIELDS:
                continue
            payload[key] = value
        return json.dumps(payload, default=str, sort_keys=True)


def setup_structured_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit JSON formatted messages."""

    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    for handler in root.handlers:
        handler.setFormatter(_JsonFormatter())
