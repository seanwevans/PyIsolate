"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import json
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
        payload = json.dumps({"func": func, "args": args, "kwargs": kwargs})
        code = "\n".join(
            [
                "import importlib, json",
                f"payload = json.loads({payload!r})",
                "module_name, func_name = payload['func'].rsplit('.', 1)",
                "mod = importlib.import_module(module_name)",
                "res = getattr(mod, func_name)(*payload['args'], **payload['kwargs'])",
                "post(res)",
            ]
        )
        self.exec(code)
        result = self.recv()
        if isinstance(result, Exception):
            # Propagate sandbox exceptions to the caller
            if isinstance(result, errors.SandboxError):
                raise result
            raise errors.SandboxError(str(result)) from result
        return result

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
