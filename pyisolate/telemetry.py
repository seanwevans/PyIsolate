"""Structured runtime telemetry events for PyIsolate."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Decision = Literal["allow", "deny", "not_evaluated", "unavailable"]


@dataclass(frozen=True)
class DenialEvent:
    """A first-class event emitted whenever a sandbox operation is denied.

    The event intentionally records both broker and kernel decisions so callers
    can distinguish userspace broker denials from future eBPF/LSM denials.
    """

    cell: str
    capability: str
    attempted_action: str
    policy_rule: str
    kernel_decision: Decision
    broker_decision: Decision

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable representation of this denial."""

        return asdict(self)
