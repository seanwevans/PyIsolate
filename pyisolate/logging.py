"""Logging helpers for PyIsolate."""

from __future__ import annotations

import logging


def setup_structured_logging(level: int = logging.INFO) -> None:
    """Configure the root logger to emit JSON formatted messages."""

    logging.basicConfig(
        level=level,
        format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
               '"component": "%(name)s", "message": "%(message)s"}',
    )

