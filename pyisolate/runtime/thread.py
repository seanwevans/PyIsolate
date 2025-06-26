"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import builtins
import json
import logging
import queue
import signal
import socket
import threading
import time
import tracemalloc
from dataclasses import dataclass
from typing import Any, Optional, Iterable

from .. import errors
from ..numa import bind_current_thread

# Precompute a sanitized builtins dict for sandbox execution.
_FORBIDDEN = {
    "eval",
    "exec",
    "compile",
    "getattr",
    "setattr",
    "delattr",
}
_SAFE_BUILTINS = {
    name: getattr(builtins, name)
    for name in dir(builtins)
    if not name.startswith("_") or name == "__import__"
}
for name in _FORBIDDEN:
    _SAFE_BUILTINS.pop(name, None)


_thread_local = threading.local()
_orig_connect = socket.socket.connect


def _guarded_connect(self: socket.socket, address: Iterable[str]) -> Any:
    allowed = getattr(_thread_local, "tcp", None)
    if allowed is not None:
        host, port = address
        if f"{host}:{port}" not in allowed:
            raise errors.PolicyError(f"connect blocked: {host}:{port}")
    return _orig_connect(self, address)


socket.socket.connect = _guarded_connect


def _sigxcpu_handler(signum, frame):
    raise errors.CPUExceeded()


signal.signal(signal.SIGXCPU, _sigxcpu_handler)


@dataclass
class Stats:
    cpu_ms: float
    mem_bytes: int


class SandboxThread(threading.Thread):
    """Thread that runs guest code and communicates via a queue."""

    def __init__(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
    ):
        super().__init__(name=name, daemon=True)
        self._logger = logging.getLogger(f"pyisolate.{name}")
        self._inbox: "queue.Queue[str]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self._cpu_time = 0.0
        self._mem_peak = 0
        self.numa_node = numa_node
        self._mem_base = 0
        self._start_time = None
        self._cgroup_path = cgroup_path
        self._trace_enabled = False
        self._syscall_log: list[str] = []

    def enable_tracing(self) -> None:
        """Start recording guest operations."""
        self._trace_enabled = True
        self._syscall_log = []

    def get_syscall_log(self) -> list[str]:
        """Return recorded guest operations."""
        return list(self._syscall_log)

    def profile(self) -> Stats:
        """Return current CPU and memory usage."""
        return self.stats

    def exec(self, src: str) -> None:
        if self._trace_enabled:
            self._syscall_log.append(src)
        self._logger.debug("exec", extra={"code": src})
        self._inbox.put(src)

    def call(self, func: str, *args, **kwargs):
        payload = json.dumps({"func": func, "args": args, "kwargs": kwargs})
        code = "\n".join(
            [
                "import importlib, json",
                f"payload = json.loads({payload!r})",
                "module_name, func_name = payload['func'].rsplit('.', 1)",
                "mod = importlib.import_module(module_name)",
                "res = object.__getattribute__(mod, func_name)(*payload['args'], **payload['kwargs'])",
                "post(res)",
            ]
        )
        self.exec(code)
        try:
            result = self.recv()
        except Exception as exc:  # sandbox raised
            if isinstance(exc, errors.SandboxError):
                raise exc
            raise errors.SandboxError(str(exc)) from exc
        return result

    def recv(self, timeout: Optional[float] = None):
        try:
            result = self._outbox.get(timeout=timeout)
            if isinstance(result, Exception):
                raise result
            return result
        except queue.Empty:
            raise errors.TimeoutError("no message received")

    def stop(self, timeout: float = 0.2) -> None:
        self._stop_event.set()
        self.join(timeout)

    def reset(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
    ) -> None:
        """Reuse this thread for a new sandbox."""
        self.name = name
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self._cpu_time = 0.0
        self._mem_peak = 0

    @property
    def stats(self):
        cpu_ms = self._cpu_time
        if self._start_time is not None:
            cpu_ms += (time.monotonic() - self._start_time) * 1000
        return Stats(cpu_ms=cpu_ms, mem_bytes=self._mem_peak)

    # internal thread run loop
    def run(self) -> None:
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        try:
            from .. import cgroup

            cgroup.attach_current(self._cgroup_path)
        except Exception:
            pass
        self._mem_base = tracemalloc.get_traced_memory()[0]
        self._cpu_time = 0.0
        self._start_time = None

        allowed_tcp = set()
        if self.policy is not None and getattr(self.policy, "tcp", None):
            allowed_tcp = set(self.policy.tcp)
        _thread_local.tcp = allowed_tcp

        local_vars = {"post": self._outbox.put, "__builtins__": _SAFE_BUILTINS}

        if self.numa_node is not None:
            bind_current_thread(self.numa_node)
            
        while not self._stop_event.is_set():
            try:
                src = self._inbox.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                start_cpu = time.thread_time()
                self._start_time = time.monotonic()
                if self._trace_enabled:
                    self._syscall_log.append(src)
                self._logger.debug("run_exec", extra={"code": src})
                exec(src, local_vars, local_vars)
                end_cpu = time.thread_time()
                self._cpu_time += (end_cpu - start_cpu) * 1000
                self._start_time = None
                cur, peak = tracemalloc.get_traced_memory()
                self._mem_peak = max(self._mem_peak, peak - self._mem_base)
            except Exception as exc:  # real impl would sanitize
                self._outbox.put(exc)
        _thread_local.tcp = set()
        
