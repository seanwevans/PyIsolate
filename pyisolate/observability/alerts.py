class AlertManager:
    """Dispatch callbacks on policy violations."""

    def __init__(self) -> None:
        self._subs: list[callable] = []

    def register(self, callback) -> None:
        self._subs.append(callback)

    def notify(self, sandbox: str, error: Exception) -> None:
        for cb in list(self._subs):
            cb(sandbox, error)
