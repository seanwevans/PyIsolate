"""Exception hierarchy for PyIsolate."""

import builtins as _builtins


class SandboxError(Exception):
    """Base class for all sandbox related errors."""


class PolicyError(SandboxError):
    """Raised when a policy violation occurs."""


class PolicyAuthError(PolicyError):
    """Raised when a policy update is not properly authenticated."""


class TimeoutError(SandboxError, _builtins.TimeoutError):
    """Raised when a sandbox operation times out."""


class MemoryExceeded(SandboxError):
    """Raised when a sandbox exceeds its memory quota."""


class CPUExceeded(SandboxError):
    """Raised when a sandbox exceeds its CPU quota."""


class WallTimeExceeded(SandboxError):
    """Raised when a sandbox exceeds its wall-clock quota."""


class OpenFilesExceeded(SandboxError):
    """Raised when a sandbox exceeds its open-files quota."""


class NetworkExceeded(SandboxError):
    """Raised when a sandbox exceeds its network operations quota."""


class OutputExceeded(SandboxError):
    """Raised when a sandbox exceeds its output quota."""


class ChildWorkExceeded(SandboxError):
    """Raised when a sandbox exceeds its concurrent child-work quota."""


class TenantQuotaExceeded(SandboxError):
    """Raised when a tenant exceeds sustained quota."""


class OwnershipError(SandboxError):
    """Raised when a moved value is accessed."""
