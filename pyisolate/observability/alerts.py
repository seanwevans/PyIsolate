import logging

logger = logging.getLogger(__name__)


class AlertManager:
    """Dispatch callbacks on policy violations."""

    def __init__(self) -> None:
        self._subs: list[callable] = []

    def register(self, callback) -> None:
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
