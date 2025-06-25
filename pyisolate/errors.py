"""Exception hierarchy for PyIsolate."""

class SandboxError(Exception):
    """Base class for all sandbox related errors."""


class PolicyError(SandboxError):
    """Raised when a policy violation occurs."""


class TimeoutError(SandboxError):
    """Raised when a sandbox operation times out."""


class MemoryExceeded(SandboxError):
    """Raised when a sandbox exceeds its memory quota."""


class CPUExceeded(SandboxError):
    """Raised when a sandbox exceeds its CPU quota."""
