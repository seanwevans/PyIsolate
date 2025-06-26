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

    pass


class MemoryExceeded(SandboxError):
    """Raised when a sandbox exceeds its memory quota."""


class CPUExceeded(SandboxError):
    """Raised when a sandbox exceeds its CPU quota."""


class OwnershipError(SandboxError):
    """Raised when a moved value is accessed."""
