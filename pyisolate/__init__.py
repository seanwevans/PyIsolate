"""PyIsolate package init.

This module exposes the high-level API described in API.md.
"""

from . import bpf  # noqa: F401
from .capabilities import (  # noqa: F401
    ROOT,
    Authority,
    AuthoritySet,
    ConnectTCP,
    CpuBudget,
    IPCChannelCapability,
    Capability,
    ClockCapability,
    FilesystemCapability,
    NetworkCapability,
    Import,
    RandomCapability,
    ReadPath,
    RootCapability,
    SecretCapability,
    SubprocessCapability,
    Token,
    WritePath,
)

try:
    from .checkpoint import checkpoint, restore
except (
    ModuleNotFoundError,
    ImportError,
) as exc:  # pragma: no cover - optional dependency
    # Trap only dependency-related import failures; let unrelated import-time
    # bugs in optional modules propagate so they remain visible to developers.
    if (
        isinstance(exc, ModuleNotFoundError)
        and exc.name
        and exc.name.split(".", 1)[0] != "cryptography"
    ):
        raise
    if isinstance(exc, ImportError) and "cryptography" not in str(exc):
        raise

    def checkpoint(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for checkpoint support")

    def restore(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for checkpoint support")


from .editor import PolicyEditor, check_fs, check_tcp, parse_policy  # noqa: F401
from .errors import (
    CPUExceeded,
    ChildWorkExceeded,
    MemoryExceeded,
    NetworkExceeded,
    OpenFilesExceeded,
    OutputExceeded,
    PolicyAuthError,
    PolicyError,
    SandboxError,
    TenantQuotaExceeded,
    TimeoutError,
    WallTimeExceeded,
)
from .logging import setup_structured_logging  # noqa: F401
from .telemetry import DenialEvent  # noqa: F401

try:
    from .migration import migrate
except (
    ModuleNotFoundError,
    ImportError,
) as exc:  # pragma: no cover - optional dependency
    # Trap only dependency-related import failures; let unrelated import-time
    # bugs in optional modules propagate so they remain visible to developers.
    if (
        isinstance(exc, ModuleNotFoundError)
        and exc.name
        and exc.name.split(".", 1)[0] != "cryptography"
    ):
        raise
    if isinstance(exc, ImportError) and "cryptography" not in str(exc):
        raise

    def migrate(*args, **kwargs):  # type: ignore[no-redef]
        raise ModuleNotFoundError("cryptography is required for migration support")


from .policy import refresh_remote, resolve_policy  # noqa: F401
from .sdk import Pipeline, sandbox  # noqa: F401
from .subset import OwnershipError, RestrictedExec  # noqa: F401
from .nogil import no_gil_readiness_report, warn_if_unsafe_native_extensions  # noqa: F401
from .supervisor import (
    BackendMode,
    DEFAULT_BACKEND,
    IMPLEMENTED_BACKENDS,
    SUPPORTED_BACKENDS,
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
    "BackendMode",
    "DEFAULT_BACKEND",
    "SUPPORTED_BACKENDS",
    "IMPLEMENTED_BACKENDS",
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
    "WallTimeExceeded",
    "OpenFilesExceeded",
    "NetworkExceeded",
    "OutputExceeded",
    "ChildWorkExceeded",
    "TenantQuotaExceeded",
    "sandbox",
    "Pipeline",
    "RestrictedExec",
    "OwnershipError",
    "Capability",
    "Authority",
    "AuthoritySet",
    "ReadPath",
    "WritePath",
    "ConnectTCP",
    "Import",
    "CpuBudget",
    "Token",
    "RootCapability",
    "ROOT",
    "set_policy_token",
    "FilesystemCapability",
    "NetworkCapability",
    "SecretCapability",
    "SubprocessCapability",
    "IPCChannelCapability",
    "ClockCapability",
    "RandomCapability",
    "PolicyEditor",
    "parse_policy",
    "check_fs",
    "check_tcp",
    "checkpoint",
    "restore",
    "migrate",
    "refresh_remote",
    "resolve_policy",
    "setup_structured_logging",
    "DenialEvent",
    "no_gil_readiness_report",
    "warn_if_unsafe_native_extensions",
    "bpf",
]

warn_if_unsafe_native_extensions()
