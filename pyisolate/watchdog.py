"""ResourceWatchdog implementation.

Periodically polls per-sandbox counters and stops sandboxes when quotas are
exceeded. The real project would use BPF perf events but this stub relies on
the ``SandboxThread.stats`` values.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from . import errors

if TYPE_CHECKING:  # pragma: no cover - circular import hints
    from .runtime.thread import SandboxThread
    from .supervisor import Supervisor


class ResourceWatchdog(threading.Thread):
    """Polls sandbox stats and enforces resource quotas."""

    def __init__(self, supervisor: "Supervisor", interval: float = 0.05):
        super().__init__(daemon=True)
        self._supervisor = supervisor
        self._interval = interval
        self._stop_event = threading.Event()

    def stop(self, timeout: float = 0.2) -> None:
        self._stop_event.set()
        self.join(timeout)

    def run(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(self._interval)
            sandboxes: list[SandboxThread] = self._supervisor.get_active_threads()
            for sb in sandboxes:
                stats = sb.stats
                if sb.cpu_quota_ms is not None and stats.cpu_ms >= sb.cpu_quota_ms:
                    sb._outbox.put(errors.CPUExceeded())
                    sb.stop()
                    continue
                if sb.mem_quota_bytes is not None and (
                    stats.mem_bytes >= sb.mem_quota_bytes
                ):
                    sb._outbox.put(errors.MemoryExceeded())
                    sb.stop()
