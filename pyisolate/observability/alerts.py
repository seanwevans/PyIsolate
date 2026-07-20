import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)

AlertCallback = Callable[[str, Exception], object]


class AlertManager:
    """Dispatch callbacks on policy violations."""

    def __init__(self) -> None:
        self._subs: list[AlertCallback] = []

    def register(self, callback: AlertCallback) -> None:
        self._subs.append(callback)

    def notify(self, sandbox: str, error: Exception) -> list[Exception]:
        errors: list[Exception] = []
        for cb in list(self._subs):
            try:
                cb(sandbox, error)
            except Exception as exc:  # pragma: no cover - exercised in tests
                errors.append(exc)
                logger.exception("alert callback %r failed for sandbox %s", cb, sandbox)
        return errors
