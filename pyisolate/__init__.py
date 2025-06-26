"""PyIsolate package init.

This module exposes the high-level API described in API.md.
"""

from .errors import (
    CPUExceeded,
    MemoryExceeded,
    PolicyError,
    SandboxError,
    TimeoutError,
)
from .supervisor import (
    Sandbox,
    Supervisor,
    list_active,
    reload_policy,
    spawn,
    shutdown,
)
from .capabilities import ROOT, Capability, Token, RootCapability

__all__ = [
    "spawn",
    "list_active",
    "Sandbox",
    "Supervisor",
    "reload_policy",
    "shutdown",
    "SandboxError",
    "PolicyError",
    "TimeoutError",
    "MemoryExceeded",
    "CPUExceeded",
    "Capability",
    "Token",
    "RootCapability",
    "ROOT",
]
