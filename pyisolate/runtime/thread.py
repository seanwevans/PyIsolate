"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import builtins
import io
import json
import logging
import os
import queue
import signal
import socket
import threading
import time
import tracemalloc
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .. import errors
from ..numa import bind_current_thread
from ..observability.trace import Tracer

_thread_local = threading.local()

_ORIG_OPEN = builtins.open


def _blocked_open(file, *args, **kwargs):
    """Restrict file access based on the current thread's policy."""

    if isinstance(file, (str, bytes, os.PathLike)):
        path = Path(file).resolve()

        allowed = getattr(_thread_local, "fs", None)

        if allowed is not None:
            if not any(path.is_relative_to(a) for a in allowed):
                raise errors.PolicyError("file access blocked")
        elif getattr(_thread_local, "active", False) and path.is_relative_to(Path("/etc")):
            raise errors.PolicyError("file access blocked")

    return _ORIG_OPEN(file, *args, **kwargs)


def _sandbox_import(name, globals=None, locals=None, fromlist=(), level=0):
    """Custom importer that provides a coarse timer to guests."""
    module = builtins.__import__(name, globals, locals, fromlist, level)
    if name == "time":

        def _perf_counter() -> float:
            return 0.0

        module = types.ModuleType("time", module.__doc__)
        module.__dict__.update({k: getattr(time, k) for k in dir(time)})
        module.perf_counter = _perf_counter
    return module


import types

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
_SAFE_BUILTINS["open"] = _blocked_open
_SAFE_BUILTINS["__import__"] = _sandbox_import


@contextmanager
def _patch(obj, attr: str, value):
    original = getattr(obj, attr)
    setattr(obj, attr, value)
    try:
        yield
    finally:
        setattr(obj, attr, original)


def _sigxcpu_handler(signum, frame):
    raise errors.CPUExceeded()


_STOP = object()


@dataclass
class Stats:
    cpu_ms: float
    mem_bytes: int
    latency: dict[str, int]
    latency_sum: float
    errors: int
    operations: int
    cost: float


class SandboxThread(threading.Thread):
    """Thread that runs guest code and communicates via a queue."""

    def __init__(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        on_violation: Optional[Callable[[str, Exception], None]] = None,
        tracer: Optional["Tracer"] = None,
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
        if allowed_imports is not None:
            self.allowed_imports = set(allowed_imports)
            self.allowed_imports.add("json")
        else:
            self.allowed_imports = None
        self._cpu_time = 0.0
        self._mem_peak = 0
        self.numa_node = numa_node
        self._mem_base = 0
        self._start_time: float | None = None
        self._on_violation = on_violation
        self._tracer = tracer or Tracer()
        self._ops = 0
        self._errors = 0
        self._latency = {"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0}
        self._latency_sum = 0.0
        self._cgroup_path = cgroup_path
        self._trace_enabled = False
        self._syscall_log: list[str] = []

    def snapshot(self) -> dict:
        """Return serializable configuration state."""
        return {
            "name": self.name,
            "policy": self.policy,
            "cpu_ms": self.cpu_quota_ms,
            "mem_bytes": self.mem_quota_bytes,
        }

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

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        payload = json.dumps({"func": func, "args": args, "kwargs": kwargs})
        code = "\n".join(
            [
                "import json",
                f"payload = json.loads({payload!r})",
                "module_name, func_name = payload['func'].rsplit('.', 1)",
                "mod = __import__(module_name, fromlist=['_'])",
                "res = object.__getattribute__(mod, func_name)(*payload['args'], **payload['kwargs'])",
                "post(res)",
            ]
        )
        self.exec(code)
        try:
            result = self.recv(timeout)
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
        self._inbox.put(_STOP)
        self.join(timeout)

    def reset(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        cgroup_path=None,
    ) -> None:
        """Reuse this thread for a new sandbox."""
        old_path = getattr(self, "_cgroup_path", None)
        self.name = name
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        if allowed_imports is not None:
            self.allowed_imports = set(allowed_imports)
            self.allowed_imports.add("json")
        else:
            self.allowed_imports = None
        self._cpu_time = 0.0
        self._mem_peak = 0
        self._cgroup_path = cgroup_path
        try:
            from .. import cgroup

            if cgroup_path is not None:
                cgroup.attach_current(cgroup_path)
            if old_path and old_path != cgroup_path:
                cgroup.delete(old_path)
        except Exception:
            pass

    @property
    def stats(self):
        cpu_ms = self._cpu_time
        if self._start_time is not None:
            cpu_ms += (time.monotonic() - self._start_time) * 1000
        cost = cpu_ms * 0.0001 + self._mem_peak * 1e-9
        return Stats(
            cpu_ms=cpu_ms,
            mem_bytes=self._mem_peak,
            latency=dict(self._latency),
            latency_sum=self._latency_sum,
            errors=self._errors,
            operations=self._ops,
            cost=cost,
        )

    # internal thread run loop
    def run(self) -> None:
        import socket


        orig_builtin_open = builtins.open
        orig_io_open = io.open
        orig_connect = socket.socket.connect
        try:
            prev_handler = signal.signal(signal.SIGXCPU, _sigxcpu_handler)
        except ValueError:
            prev_handler = None

        with ExitStack() as stack:
            stack.enter_context(_patch(builtins, "open", _blocked_open))
            stack.enter_context(_patch(io, "open", _blocked_open))


            orig_connect = socket.socket.connect

            def _guarded_connect(self_socket: socket.socket, address: Iterable[str]) -> Any:
                allowed = getattr(_thread_local, "tcp", None)
                if allowed is not None:
                    host, port = address
                    if f"{host}:{port}" not in allowed:
                        raise errors.PolicyError(f"connect blocked: {host}:{port}")
                return orig_connect(self_socket, address)

            stack.enter_context(
                _patch(socket.socket, "connect", _guarded_connect)
            )

            _thread_local.active = True

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

            local_vars = {"post": self._outbox.put}

            if self.numa_node is not None:
                bind_current_thread(self.numa_node)

            while True:
                src = self._inbox.get()
                if src is _STOP:
                    break

                allowed_tcp = set()
                allowed_fs = None
                if self.policy is not None:
                    if getattr(self.policy, "tcp", None):
                        allowed_tcp = set(self.policy.tcp)
                    if getattr(self.policy, "fs", None):
                        allowed_fs = [Path(p).resolve() for p in self.policy.fs]
                _thread_local.tcp = allowed_tcp
                _thread_local.fs = allowed_fs

                if self.allowed_imports is not None:
                    import builtins as _builtins

                    from .imports import CapabilityImporter

                    builtins_dict = _builtins.__dict__.copy()
                    builtins_dict["__import__"] = CapabilityImporter(
                        self.allowed_imports
                    )
                    builtins_dict["open"] = _blocked_open
                    local_vars["__builtins__"] = builtins_dict
                else:
                    local_vars["__builtins__"] = _SAFE_BUILTINS.copy()

                self._ops += 1
                op_start = time.monotonic()
                with self._tracer.start_span(f"sandbox:{self.name}"):
                    try:
                        start_cpu = time.thread_time()
                        self._start_time = time.monotonic()
                        exec(src, local_vars, local_vars)
                        end_cpu = time.thread_time()
                        self._cpu_time += (end_cpu - start_cpu) * 1000
                        self._start_time = None
                        cur, peak = tracemalloc.get_traced_memory()
                        self._mem_peak = max(self._mem_peak, peak - self._mem_base)
                        if (
                            self.cpu_quota_ms is not None
                            and self._cpu_time > self.cpu_quota_ms
                        ):
                            raise errors.CPUExceeded()
                        if (
                            self.mem_quota_bytes is not None
                            and self._mem_peak > self.mem_quota_bytes
                        ):
                            raise errors.MemoryExceeded()
                    except Exception as exc:  # real impl would sanitize
                        self._errors += 1
                        self._start_time = None
                        if self._on_violation and isinstance(exc, errors.PolicyError):
                            self._on_violation(self.name, exc)
                        self._outbox.put(exc)
                    finally:
                        self._start_time = None
                        duration = (time.monotonic() - op_start) * 1000
                        self._latency_sum += duration
                        if duration <= 0.5:
                            self._latency["0.5"] += 1
                        elif duration <= 1:
                            self._latency["1"] += 1
                        elif duration <= 5:
                            self._latency["5"] += 1
                        elif duration <= 10:
                            self._latency["10"] += 1
                        else:
                            self._latency["inf"] += 1
            _thread_local.active = False
        finally:
            if prev_handler is not None:
                signal.signal(signal.SIGXCPU, prev_handler)
            socket.socket.connect = orig_connect
            io.open = orig_io_open
            builtins.open = orig_builtin_open
