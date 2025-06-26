"""PyIsolate package init.

This module exposes the high-level API described in API.md.
"""

from .editor import PolicyEditor, check_fs, check_tcp, parse_policy
from .errors import (
    CPUExceeded,
    MemoryExceeded,
    PolicyError,
    PolicyAuthError,
    SandboxError,
    TimeoutError,
)
from .supervisor import (
    Sandbox,
    Supervisor,
    list_active,
    reload_policy,
    set_policy_token,
    spawn,
    shutdown,
    spawn,
)
from .subset import OwnershipError, RestrictedExec

from .capabilities import ROOT, Capability, Token, RootCapability
from .checkpoint import checkpoint, restore
from .migration import migrate
from .policy import refresh_remote

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
]
