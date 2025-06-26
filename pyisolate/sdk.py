"""High level SDK helpers."""

from __future__ import annotations

from typing import Any, Callable

from .supervisor import spawn


def sandbox(
    policy: str | None = None, timeout: str | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a function to run inside a sandbox when called."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sb = spawn(func.__name__, policy=policy)
            try:
                return sb.call(f"{func.__module__}.{func.__name__}", *args, **kwargs)
            finally:
                sb.close()

        return wrapper

    return decorator


class Pipeline:
    """Sequential sandboxed stages."""

    def __init__(self) -> None:
        self._stages: list[tuple[str, str | None]] = []

    def add_stage(
        self, stage: str | Callable[[Any], Any], policy: str | None = None
    ) -> "Pipeline":
        """Register a stage by dotted path or callable."""
        if callable(stage):
            dotted = f"{stage.__module__}.{stage.__name__}"
        else:
            dotted = stage
        self._stages.append((dotted, policy))
        return self

    def run(self, data: Any) -> Any:
        """Run data through all stages sequentially."""
        value = data
        for dotted, policy in self._stages:
            name = dotted.rsplit(".", 1)[-1]
            with spawn(name, policy=policy) as sb:
                value = sb.call(dotted, value)
        return value
