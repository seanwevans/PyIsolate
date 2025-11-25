"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import builtins
import io
import logging
import os
import queue
import signal
import socket
import threading
import time
import tracemalloc
import types
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .. import errors
from ..numa import bind_current_thread
from ..observability.trace import Tracer

_thread_local = threading.local()

_ORIG_OPEN = builtins.open
_ORIG_SOCKET_CONNECT = socket.socket.connect


def _blocked_open(file, *args, **kwargs):
    """Restrict file access based on the current thread's policy."""

    if isinstance(file, os.PathLike):
        file = os.fspath(file)

    if isinstance(file, (str, bytes)):
        path = Path(file).resolve(strict=False)

        allowed = getattr(_thread_local, "fs", None)

        if allowed is not None:
            if not any(path.is_relative_to(a) for a in allowed):
                raise errors.PolicyError("file access blocked")
        elif getattr(_thread_local, "active", False) and path.is_relative_to(
            Path("/etc")
        ):
            raise errors.PolicyError("file access blocked")

    return _ORIG_OPEN(file, *args, **kwargs)


def _guarded_connect(self_socket: socket.socket, address: Iterable[str]):
    allowed = getattr(_thread_local, "tcp", None)
    if allowed is not None:
        if isinstance(address, tuple):
            host, port, *_ = address
        else:
            host, port = address
        if f"{host}:{port}" not in allowed:
            raise errors.PolicyError(f"connect blocked: {host}:{port}")
    return _ORIG_SOCKET_CONNECT(self_socket, address)


def _wrap_module(name: str, module):
    base = name.split(".")[0]
    if base == "time":

        def _perf_counter() -> float:
            return 0.0

        mod = types.ModuleType("time", module.__doc__)
        mod.__dict__.update({k: getattr(time, k) for k in dir(time)})
        mod.perf_counter = _perf_counter
        return mod
    if base == "io":
        mod = types.ModuleType("io", module.__doc__)
        mod.__dict__.update({k: getattr(io, k) for k in dir(io)})
        mod.open = _blocked_open
        return mod
    if base == "socket":
        mod = types.ModuleType("socket", module.__doc__)
        mod.__dict__.update({k: getattr(socket, k) for k in dir(socket)})

        class GuardedSocket(socket.socket):
            connect = _guarded_connect

        mod.socket = GuardedSocket
        return mod
    if base == "pathlib":
        mod = types.ModuleType("pathlib", module.__doc__)
        mod.__dict__.update({k: getattr(module, k) for k in dir(module)})

        class SandboxedPath(module.Path):
            def open(
                self,
                mode="r",
                buffering=-1,
                encoding=None,
                errors=None,
                newline=None,
            ):
                if "b" not in mode:
                    encoding = io.text_encoding(encoding)
                return _blocked_open(self, mode, buffering, encoding, errors, newline)

        mod.Path = SandboxedPath
        return mod
    return module


def _sandbox_import(name, globals=None, locals=None, fromlist=(), level=0):
    module = builtins.__import__(name, globals, locals, fromlist, level)
    return _wrap_module(name, module)


def _make_importer(allowed: Optional[Iterable[str]]):
    if allowed is None:
        return _sandbox_import
    allowed_set = {name.split(".")[0] for name in allowed}

    def _import(name, globals=None, locals=None, fromlist=(), level=0):
        base = name.split(".")[0]
        if base not in allowed_set:
            raise errors.PolicyError(f"import of {name!r} is not permitted")
        module = builtins.__import__(name, globals, locals, fromlist, level)
        return _wrap_module(name, module)

    return _import


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


@dataclass
class _CgroupAttach:
    """Control message to (re)attach the sandbox thread to a cgroup."""

    old_path: Path | None


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
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        if allowed_imports is not None:
            self.allowed_imports = set(allowed_imports)
        else:
            self.allowed_imports = None
        self._cpu_time = 0.0
        self._mem_peak = 0
        self.numa_node = numa_node
        self._bound_numa_node: int | None = None
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
            "allowed_imports": sorted(self.allowed_imports)
            if self.allowed_imports is not None
            else None,
            "numa_node": self.numa_node,
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
        if self._trace_enabled:
            self._syscall_log.append(f"call {func}")
        self._logger.debug("call", extra={"func": func})
        self._inbox.put(("call", func, args, kwargs))
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
        numa_node: Optional[int] = None,
        cgroup_path=None,
    ) -> None:
        """Reuse this thread for a new sandbox."""
        old_path = getattr(self, "_cgroup_path", None)
        self.name = name
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self.numa_node = numa_node
        self._bound_numa_node = None
        if allowed_imports is not None:
            self.allowed_imports = set(allowed_imports)
        else:
            self.allowed_imports = None
        self._cpu_time = 0.0
        self._mem_peak = 0
        self._ops = 0
        self._errors = 0
        self._latency = {"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0}
        self._latency_sum = 0.0
        self._trace_enabled = False
        self._syscall_log = []
        self._start_time = None
        self._cgroup_path = cgroup_path
        # Request the sandbox thread to (re)attach itself to the new cgroup.
        # The attachment must happen from the sandbox thread's context.
        self._inbox.put(_CgroupAttach(old_path))

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
        try:
            prev_handler = signal.signal(signal.SIGXCPU, _sigxcpu_handler)
        except ValueError:
            prev_handler = None

        try:
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
            self._bound_numa_node = self.numa_node

            while True:
                payload = self._inbox.get()
                if payload is _STOP:
                    break
                if isinstance(payload, _CgroupAttach):
                    try:
                        from .. import cgroup

                        cgroup.attach_current(self._cgroup_path)
                        if payload.old_path and payload.old_path != self._cgroup_path:
                            cgroup.delete(payload.old_path)
                    except Exception:
                        pass
                    continue

                if self.numa_node != self._bound_numa_node:
                    if self.numa_node is not None:
                        bind_current_thread(self.numa_node)
                    self._bound_numa_node = self.numa_node

                allowed_tcp = None
                allowed_fs = None
                if self.policy is not None:
                    if getattr(self.policy, "tcp", None):
                        allowed_tcp = set(self.policy.tcp)
                    if getattr(self.policy, "fs", None):
                        allowed_fs = [
                            Path(p).resolve(strict=False) for p in self.policy.fs
                        ]
                if allowed_tcp is None:
                    if hasattr(_thread_local, "tcp"):
                        delattr(_thread_local, "tcp")
                else:
                    _thread_local.tcp = allowed_tcp
                _thread_local.fs = allowed_fs

                builtins_dict = _SAFE_BUILTINS.copy()
                builtins_dict["open"] = _blocked_open
                builtins_dict["__import__"] = _make_importer(self.allowed_imports)
                local_vars["__builtins__"] = builtins_dict

                self._ops += 1
                op_start = time.monotonic()
                with self._tracer.start_span(f"sandbox:{self.name}"):
                    try:
                        start_cpu = time.thread_time()
                        self._start_time = time.monotonic()
                        if isinstance(payload, tuple):
                            kind, func, args, kwargs = payload
                            if kind == "call":
                                importer = builtins_dict["__import__"]
                                try:
                                    module_name, func_name = func.rsplit(".", 1)
                                except ValueError as exc:
                                    raise errors.SandboxError(
                                        "call target {!r} must include a module path (e.g. 'module.func')".format(
                                            func
                                        )
                                    ) from exc
                                mod = importer(module_name, fromlist=["_"])
                                res = object.__getattribute__(mod, func_name)(
                                    *args, **kwargs
                                )
                                self._outbox.put(res)
                            else:
                                raise errors.SandboxError("unknown operation")
                        else:
                            exec(payload, local_vars, local_vars)
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
