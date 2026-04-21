"""Logging helpers for PyIsolate."""

from __future__ import annotations

import logging
from json import dumps


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        for key in ("event", "supervisor_id", "cell_id", "reason"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        return dumps(payload, sort_keys=True)


def setup_structured_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit JSON formatted messages."""
    handler = logging.StreamHandler()
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
