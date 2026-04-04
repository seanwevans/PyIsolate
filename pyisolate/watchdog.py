"""ResourceWatchdog implementation.

Consumes events from the BPF ring buffer and stops sandboxes when quotas are
breached. Events are dictionaries with the sandbox ``name`` and current
``cpu_ms`` and ``rss_bytes`` counters.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING

from . import errors

if TYPE_CHECKING:
    from .supervisor import Supervisor

logger = logging.getLogger(__name__)


class ResourceWatchdog(threading.Thread):
    """Polls sandbox stats and enforces resource quotas."""

    def __init__(self, supervisor: "Supervisor", interval: float = 0.05):
        super().__init__(daemon=True)
        self._supervisor = supervisor
        self._interval = interval
        self._stop_event = threading.Event()
        self._rb_iter = None

    def stop(self, timeout: float = 0.2) -> None:
        self._stop_event.set()
        self.join(timeout)

    def run(self) -> None:
        while not self._stop_event.is_set():
            if self._rb_iter is None:
                self._rb_iter = self._supervisor._bpf.open_ring_buffer()
            try:
                event = next(self._rb_iter)
            except StopIteration:
                self._rb_iter = None
                time.sleep(self._interval)
                continue
            except Exception:
                logger.exception("watchdog ring-buffer iterator failed; resetting")
                self._rb_iter = None
                time.sleep(self._interval)
                continue

            if not isinstance(event, Mapping):
                logger.warning("watchdog ignored non-mapping event payload: %r", event)
                continue

            name = event.get("name")
            cpu_ms = event.get("cpu_ms", 0)
            rss = event.get("rss_bytes", 0)
            active = {t.name: t for t in self._supervisor.get_active_threads()}
            sb = active.get(name)
            if not sb:
                continue
            if sb.cpu_quota_ms is not None and cpu_ms >= sb.cpu_quota_ms:
                try:
                    sb._outbox.put(errors.CPUExceeded())
                    sb.stop()
                except Exception:
                    logger.exception(
                        "watchdog failed to stop sandbox %r after CPU quota breach", name
                    )
                continue
            if sb.mem_quota_bytes is not None and rss >= sb.mem_quota_bytes:
                try:
                    sb._outbox.put(errors.MemoryExceeded())
                    sb.stop()
                except Exception:
                    logger.exception(
                        "watchdog failed to stop sandbox %r after memory quota breach", name
                    )
