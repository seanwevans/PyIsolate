"""PyIsolate package init.

This module exposes the high-level API described in API.md.
"""

from . import bpf  # noqa: F401
from .capabilities import ROOT, Capability, RootCapability, Token  # noqa: F401

try:
    from .checkpoint import checkpoint, restore
except Exception:  # pragma: no cover - optional dependency

    def checkpoint(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for checkpoint support")

    def restore(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for checkpoint support")


from .editor import PolicyEditor, check_fs, check_tcp, parse_policy  # noqa: F401
from .errors import (
    CPUExceeded,
    MemoryExceeded,
    PolicyAuthError,
    PolicyError,
    SandboxError,
    TimeoutError,
)
from .logging import setup_structured_logging  # noqa: F401

try:
    from .migration import migrate
except Exception:  # pragma: no cover - optional dependency

    def migrate(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for migration support")


from .policy import refresh_remote  # noqa: F401
from .sdk import Pipeline, sandbox  # noqa: F401
from .subset import OwnershipError, RestrictedExec  # noqa: F401
from .supervisor import (
    Sandbox,
    Supervisor,
    list_active,
    reload_policy,
    set_policy_token,
    shutdown,
    spawn,
)  # noqa: F401

__all__ = [
    "spawn",
    "list_active",
    "Sandbox",
    "Supervisor",
    "reload_policy",
    "shutdown",
    "SandboxError",
    "PolicyError",
    "PolicyAuthError",
    "TimeoutError",
    "MemoryExceeded",
    "CPUExceeded",
    "sandbox",
    "Pipeline",
    "RestrictedExec",
    "OwnershipError",
    "Capability",
    "Token",
    "RootCapability",
    "ROOT",
    "set_policy_token",
    "PolicyEditor",
    "parse_policy",
    "check_fs",
    "check_tcp",
    "checkpoint",
    "restore",
    "migrate",
    "refresh_remote",
    "setup_structured_logging",
    "bpf",
]
