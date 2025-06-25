"""Supervisor agent.

This module manages sandbox threads and serves as the entry point for spawning
sandboxes. It is intentionally minimal and not security hardened. Real isolation
requires eBPF enforcement which is not implemented here.
"""

from __future__ import annotations

import threading
from typing import Dict, Optional

from .runtime.thread import SandboxThread


class Sandbox:
    """Handle to a sandbox thread."""

    def __init__(self, thread: SandboxThread):
        self._thread = thread

    def exec(self, src: str) -> None:
        """Execute Python source inside the sandbox."""
        self._thread.exec(src)

    def call(self, func: str, *args, **kwargs):
        """Call a dotted function inside the sandbox."""
        return self._thread.call(func, *args, **kwargs)

    def recv(self, timeout: Optional[float] = None):
        """Receive a posted object from the sandbox."""
        return self._thread.recv(timeout)

    def close(self, timeout: float = 0.2) -> None:
        self._thread.stop(timeout)

    @property
    def stats(self):
        return self._thread.stats


class Supervisor:
    """Main supervisor owning all sandboxes."""

    def __init__(self):
        self._sandboxes: Dict[str, SandboxThread] = {}
        self._lock = threading.Lock()

    def spawn(self, name: str, policy=None) -> Sandbox:
        """Create and start a sandbox thread."""
        thread = SandboxThread(name=name, policy=policy)
        thread.start()
        with self._lock:
            self._sandboxes[name] = thread
        # Remove references to any terminated sandboxes
        self._cleanup()
        return Sandbox(thread)

    def list_active(self) -> Dict[str, Sandbox]:
        """Return currently active sandboxes."""
        self._cleanup()
        with self._lock:
            return {name: Sandbox(t) for name, t in self._sandboxes.items() if t.is_alive()}

    def _cleanup(self) -> None:
        """Remove dead sandboxes from the registry."""
        with self._lock:
            dead = [n for n, t in self._sandboxes.items() if not t.is_alive()]
            for n in dead:
                del self._sandboxes[n]


_supervisor = Supervisor()


# Public API
spawn = _supervisor.spawn
list_active = _supervisor.list_active

