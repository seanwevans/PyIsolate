"""High level SDK helpers."""

from __future__ import annotations

import re
import secrets
from typing import Any, Callable

from . import supervisor
from .policy import Policy, resolve_policy

_SANDBOX_NAME_MAX_LEN = 64
_SANDBOX_NAME_SUFFIX_BYTES = 4
_INVALID_NAME_CHARS = re.compile(r"[^A-Za-z0-9_-]+")


def _sandbox_name_prefix(module: str, function: str, *parts: object) -> str:
    """Return a debuggable sandbox-name prefix accepted by the supervisor."""
    raw_parts = [module, *(str(part) for part in parts), function]
    prefix = "-".join(part for part in raw_parts if part)
    prefix = _INVALID_NAME_CHARS.sub("-", prefix).strip("-_")
    prefix = re.sub(r"[-_]{2,}", "-", prefix)
    return prefix or "sandbox"


def _unique_sandbox_name(module: str, function: str, *parts: object) -> str:
    """Build a unique supervisor-safe sandbox name no longer than 64 chars."""
    suffix = secrets.token_hex(_SANDBOX_NAME_SUFFIX_BYTES)
    separator = "-"
    max_prefix_len = _SANDBOX_NAME_MAX_LEN - len(separator) - len(suffix)

    prefix = _sandbox_name_prefix(module, function, *parts)
    if len(prefix) > max_prefix_len:
        # Keep the function/stage portion visible at the end of the prefix while
        # retaining as much module context as fits before it.
        prefix = prefix[-max_prefix_len:].lstrip("-_") or prefix[:max_prefix_len]

    name = f"{prefix}{separator}{suffix}"
    if supervisor.NAME_PATTERN.fullmatch(name) is None:
        # The default supervisor pattern permits the sanitized alphabet above.
        # If callers have installed a stricter pattern, fail with the same kind
        # of validation error spawn() would raise, but before starting work.
        raise ValueError("Sandbox name contains invalid characters")
    return name


def sandbox(
    policy: str | Policy | dict | None = None, timeout: float | None = None
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorate a function to run inside a sandbox when called.

    Parameters
    ----------
    policy:
        Name of the policy (or Policy/dict) to apply to the sandbox.
    timeout:
        Seconds to wait for the sandboxed call to complete before raising
        :class:`pyisolate.errors.TimeoutError`.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        target = f"{func.__module__}.{func.__name__}"

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            resolved_policy = resolve_policy(policy)
            sb = supervisor.spawn(
                _unique_sandbox_name(func.__module__, func.__name__),
                policy=resolved_policy,
                allowed_imports=[func.__module__],
            )
            try:
                return sb.call(target, *args, timeout=timeout, **kwargs)
            finally:
                sb.close()

        return wrapper

    return decorator


class Pipeline:
    """Sequential sandboxed stages."""

    def __init__(self) -> None:
        self._stages: list[tuple[str, str | Policy | dict | None]] = []

    def add_stage(
        self,
        stage: str | Callable[[Any], Any],
        policy: str | Policy | dict | None = None,
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
        for index, (dotted, policy) in enumerate(self._stages):
            module, _, name = dotted.rpartition(".")
            resolved_policy = resolve_policy(policy)
            allowed = [module] if module else None
            sandbox_name = _unique_sandbox_name(module, name, f"stage-{index}")
            with supervisor.spawn(
                sandbox_name, policy=resolved_policy, allowed_imports=allowed
            ) as sb:
                value = sb.call(dotted, value)
        return value
