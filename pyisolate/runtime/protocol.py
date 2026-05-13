"""Explicit minimal cell ABI between trusted and untrusted planes.

The trusted control-plane (supervisor, broker, metrics, policy engine) communicates
with untrusted sandbox threads via a fixed vocabulary only.  The public cell ABI is
intentionally tiny: ``exec``, ``call``, ``post``, ``recv``, ``log``, ``metric``, and
``request``.  Any operation outside this vocabulary must be expressed as a broker
capability request instead of growing the guest surface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

ABI_VERSION = 1
"""Monotonic version for the frozen cell ABI."""


class CellOp(str, Enum):
    """The complete public operation set exposed by a cell."""

    EXEC = "exec"
    CALL = "call"
    POST = "post"
    RECV = "recv"
    LOG = "log"
    METRIC = "metric"
    REQUEST = "request"


CELL_ABI: tuple[CellOp, ...] = (
    CellOp.EXEC,
    CellOp.CALL,
    CellOp.POST,
    CellOp.RECV,
    CellOp.LOG,
    CellOp.METRIC,
    CellOp.REQUEST,
)
"""Canonical ordered list of operations in the minimal cell ABI."""

CELL_ABI_NAMES: tuple[str, ...] = tuple(op.value for op in CELL_ABI)
"""String names for documentation, validation, and tests."""


@dataclass(frozen=True)
class CellABI:
    """Description of the frozen guest/control protocol surface."""

    version: int = ABI_VERSION
    operations: tuple[str, ...] = CELL_ABI_NAMES

    def allows(self, op: str | CellOp) -> bool:
        """Return whether *op* is part of the frozen ABI."""

        name = op.value if isinstance(op, CellOp) else op
        return name in self.operations


MINIMAL_CELL_ABI = CellABI()
"""Runtime constant used by conformance checks to pin the cell surface."""


@dataclass(frozen=True)
class CapabilityHandle:
    """Opaque handle bound to a control-plane capability."""

    kind: str
    subject: str


@dataclass(frozen=True)
class ExecRequest:
    """Execute source code in the workload plane."""

    source: str
    op: CellOp = CellOp.EXEC


@dataclass(frozen=True)
class CallRequest:
    """Call a dotted function path in the workload plane."""

    target: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    op: CellOp = CellOp.CALL


@dataclass(frozen=True)
class RecvRequest:
    """Receive the next message from the cell channel."""

    timeout: float | None = None
    op: CellOp = CellOp.RECV


@dataclass(frozen=True)
class PostEvent:
    """Guest-to-supervisor message sent with ``post``."""

    message: Any
    op: CellOp = CellOp.POST


@dataclass(frozen=True)
class LogEvent:
    """Structured guest log record emitted on the cell channel."""

    level: str
    message: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    op: CellOp = CellOp.LOG


@dataclass(frozen=True)
class MetricEvent:
    """Metric datapoint emitted on the cell channel."""

    name: str
    value: int | float
    tags: Mapping[str, str] = field(default_factory=dict)
    op: CellOp = CellOp.METRIC


@dataclass(frozen=True)
class BrokerRequest:
    """Request for a privileged broker action through an explicit capability."""

    capability: str
    action: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    op: CellOp = CellOp.REQUEST


@dataclass(frozen=True)
class AttachCgroupRequest:
    """Control-plane request to (re)attach to a cgroup path.

    This is internal supervisor plumbing, not part of the public cell ABI.
    """

    old_path: Path | None
    msg_id: int = 0


@dataclass(frozen=True)
class StopRequest:
    """Sentinel request indicating sandbox thread termination.

    This is internal supervisor plumbing, not part of the public cell ABI.
    """


@dataclass(frozen=True)
class ControlRequest:
    """Authenticated control operation crossing plane boundaries.

    Supervisor control requests are outside the guest ABI and must carry an
    explicit root or policy capability.
    """

    op: str
    capability: CapabilityHandle
    payload: dict[str, Any]
