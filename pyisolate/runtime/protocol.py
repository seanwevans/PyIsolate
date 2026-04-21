"""Explicit request protocol between trusted and untrusted planes.

The trusted control-plane (supervisor, broker, metrics, policy engine) communicates
with untrusted sandbox threads via structured message types only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CapabilityHandle:
    """Opaque handle bound to a control-plane capability."""

    kind: str
    subject: str


@dataclass(frozen=True)
class ExecRequest:
    """Execute source code in the workload plane."""

    source: str


@dataclass(frozen=True)
class CallRequest:
    """Call a dotted function path in the workload plane."""

    target: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


@dataclass(frozen=True)
class AttachCgroupRequest:
    """Control-plane request to (re)attach to a cgroup path."""

    old_path: Path | None


@dataclass(frozen=True)
class StopRequest:
    """Sentinel request indicating sandbox thread termination."""


@dataclass(frozen=True)
class ControlRequest:
    """Authenticated control operation crossing plane boundaries."""

    op: str
    capability: CapabilityHandle
    payload: dict[str, Any]
