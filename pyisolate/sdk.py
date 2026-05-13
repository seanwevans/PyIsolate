"""High level SDK helpers."""

from __future__ import annotations

from typing import Any, Callable

from .supervisor import BackendMode, DEFAULT_BACKEND, spawn


def sandbox(
    policy: str | None = None,
    timeout: float | None = None,
    backend: BackendMode = DEFAULT_BACKEND,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a function to run inside a sandbox when called.

    Parameters
    ----------
    policy:
        Name of the policy to apply to the sandbox.
    timeout:
        Seconds to wait for the sandboxed call to complete before raising
        :class:`pyisolate.errors.TimeoutError`.
    backend:
        Isolation backend: ``"subinterpreter"`` for an execution cell, or
        explicit boundary modes ``"process"`` / ``"microvm"`` when available.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sb = spawn(func.__name__, policy=policy, backend=backend)
            try:
                return sb.call(
                    f"{func.__module__}.{func.__name__}",
                    *args,
                    timeout=timeout,
                    **kwargs,
                )
            finally:
                sb.close()

        return wrapper

    return decorator


class Pipeline:
    """Sequential sandboxed stages."""

    def __init__(self) -> None:
        self._stages: list[tuple[str, str | None, BackendMode]] = []

    def add_stage(
        self,
        stage: str | Callable[[Any], Any],
        policy: str | None = None,
        backend: BackendMode = DEFAULT_BACKEND,
    ) -> "Pipeline":
        """Register a stage by dotted path or callable."""
        if callable(stage):
            dotted = f"{stage.__module__}.{stage.__name__}"
        else:
            dotted = stage
        self._stages.append((dotted, policy, backend))
        return self

    def run(self, data: Any) -> Any:
        """Run data through all stages sequentially."""
        value = data
        for dotted, policy, backend in self._stages:
            name = dotted.rsplit(".", 1)[-1]
            with spawn(name, policy=policy, backend=backend) as sb:
                value = sb.call(dotted, value)
        return value
