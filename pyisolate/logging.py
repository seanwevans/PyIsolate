"""Logging helpers for PyIsolate."""

from __future__ import annotations

import json
import logging


class JSONFormatter(logging.Formatter):
    """Render each log record as one valid JSON object.

    Building the JSON by string-templating ``%(message)s`` (and the logger
    name) produced invalid JSON whenever a value contained a quote, backslash,
    or newline, which downstream log pipelines would fail to parse.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "component": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_structured_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit JSON formatted messages."""

    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logging.basicConfig(level=level, handlers=[handler])
