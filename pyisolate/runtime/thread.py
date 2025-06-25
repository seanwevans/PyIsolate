"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import queue
import threading
from types import ModuleType
from typing import Any, Optional

from .. import errors


class SandboxThread(threading.Thread):
    """Thread that runs guest code and communicates via a queue."""

    def __init__(self, name: str, policy=None):
        super().__init__(name=name, daemon=True)
        self._inbox: "queue.Queue[str]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self.policy = policy

    def exec(self, src: str) -> None:
        self._inbox.put(src)

    def call(self, func: str, *args, **kwargs):
        code = f"import importlib, builtins\n" \
               f"module_name, func_name = '{func}'.rsplit('.', 1)\n" \
               f"mod = importlib.import_module(module_name)\n" \
               f"res = getattr(mod, func_name)(*{args!r}, **{kwargs!r})\n" \
               f"post(res)"
        self.exec(code)
        return self.recv()

    def recv(self, timeout: Optional[float] = None):
        try:
            return self._outbox.get(timeout=timeout)
        except queue.Empty:
            raise errors.TimeoutError("no message received")

    def stop(self, timeout: float = 0.2) -> None:
        self._stop_event.set()
        self.join(timeout)

    # stats placeholder
    @property
    def stats(self):
        return type("Stats", (), {"cpu_ms": 0, "mem_bytes": 0})()

    # internal thread run loop
    def run(self) -> None:
        local_vars = {"post": self._outbox.put}
        while not self._stop_event.is_set():
            try:
                src = self._inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                exec(src, local_vars, local_vars)
            except Exception as exc:  # real impl would sanitize
                self._outbox.put(exc)
