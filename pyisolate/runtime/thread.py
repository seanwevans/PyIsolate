"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import builtins
import ctypes
import io
import logging
import os
import queue
import random
import secrets as pysecrets
import signal
import socket
import subprocess
import threading
import time
import tracemalloc
import types
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .. import errors
from .protocol import (
    AttachCgroupRequest,
    CallRequest,
    ExecRequest,
    StopRequest,
)
from ..capabilities import ClockCapability
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

        fs_cap = getattr(_thread_local, "fs_capability", None)
        allowed = getattr(_thread_local, "fs", None)
        if fs_cap is not None:
            if not fs_cap.allows(path):
                raise errors.PolicyError("file access blocked")
        elif allowed is not None:
            if not any(path.is_relative_to(a) for a in allowed):
                raise errors.PolicyError("file access blocked")
        elif getattr(_thread_local, "active", False):
            raise errors.PolicyError("file access blocked")

    return _ORIG_OPEN(file, *args, **kwargs)


def _guarded_connect(self_socket: socket.socket, address: Iterable[str]):
    net_cap = getattr(_thread_local, "net_capability", None)
    allowed = getattr(_thread_local, "tcp", None)
    if isinstance(address, tuple):
        host, port, *_ = address
    else:
        host, port = address
    if net_cap is not None:
        if not net_cap.allows(str(host), int(port)):
            raise errors.PolicyError(f"connect blocked: {host}:{port}")
    elif allowed is not None:
        if f"{host}:{port}" not in allowed:
            raise errors.PolicyError(f"connect blocked: {host}:{port}")
    else:
        raise errors.PolicyError(f"connect blocked: {host}:{port}")
    return _ORIG_SOCKET_CONNECT(self_socket, address)


def _blocked_subprocess_run(*args, **kwargs):
    cap = getattr(_thread_local, "subprocess_capability", None)
    if cap is None:
        raise errors.PolicyError("subprocess access blocked")
    return cap.run(*args, **kwargs)


def _guarded_urandom(n: int) -> bytes:
    cap = getattr(_thread_local, "random_capability", None)
    if cap is None:
        raise errors.PolicyError("randomness access blocked")
    return cap.bytes(n)


def _wrap_module(name: str, module):
    base = name.split(".")[0]
    if base == "time":
        def _require_clock() -> ClockCapability:
            cap = getattr(_thread_local, "clock_capability", None)
            return cap

        def _time() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.time()

        def _monotonic() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.monotonic()

        def _perf_counter() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.monotonic()

        mod = types.ModuleType("time", module.__doc__)
        mod.__dict__.update({k: getattr(time, k) for k in dir(time)})
        mod.time = _time
        mod.monotonic = _monotonic
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
    if base == "subprocess":
        mod = types.ModuleType("subprocess", module.__doc__)
        mod.__dict__.update({k: getattr(subprocess, k) for k in dir(subprocess)})
        mod.run = _blocked_subprocess_run
        return mod
    if base == "os":
        mod = types.ModuleType("os", module.__doc__)
        mod.__dict__.update({k: getattr(os, k) for k in dir(os)})
        mod.urandom = _guarded_urandom
        return mod
    if base == "secrets":
        mod = types.ModuleType("secrets", module.__doc__)
        mod.__dict__.update({k: getattr(pysecrets, k) for k in dir(pysecrets)})
        mod.token_bytes = _guarded_urandom
        return mod
    if base == "random":
        mod = types.ModuleType("random", module.__doc__)
        mod.__dict__.update({k: getattr(random, k) for k in dir(random)})
        mod.randbytes = _guarded_urandom
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


class _KillRequest(Exception):
    """Internal exception used for asynchronous forced thread shutdown."""


@dataclass
class Stats:
    cell_id: str
    state: str
    start_reason: str | None
    stop_reason: str | None
    cpu_ms: float
    mem_bytes: int
    mem_hwm_bytes: int
    latency: dict[str, int]
    latency_sum: float
    scheduler_latency_ms: dict[str, int]
    scheduler_latency_ms_sum: float
    kill_latency_ms: float
    policy_denials: int
    quota_breaches: int
    errors: int
    operations: int
    cost: float


class SandboxThread(threading.Thread):
    """Thread that runs guest code and communicates via a queue."""

    @staticmethod
    def _merge_allowed_imports(policy, allowed_imports: Optional[Iterable[str]]):
        imports: set[str] = set()
        if policy is not None and getattr(policy, "imports", None):
            imports.update(policy.imports)

        allowed_imports_provided = allowed_imports is not None
        if allowed_imports_provided:
            imports.update(allowed_imports)

        if imports or allowed_imports_provided:
            return imports
        return None

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
        capabilities: Optional[dict[str, Any]] = None,
    ):
        super().__init__(name=name, daemon=True)
        self._logger = logging.getLogger(f"pyisolate.{name}")
        self.cell_id = uuid.uuid4().hex
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self.allowed_imports = self._merge_allowed_imports(policy, allowed_imports)
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
        self._capabilities = dict(capabilities or {})
        self._quarantine_reason: str | None = None
        self._state = "init"
        self._start_reason: str | None = "spawn"
        self._stop_reason: str | None = None
        self._policy_denials = 0
        self._quota_breaches = 0
        self._scheduler_latency = {"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0}
        self._scheduler_latency_sum = 0.0
        self._kill_latency_ms = 0.0
        self._enqueued_at: dict[int, float] = {}

    def _enqueue(self, payload: Any) -> None:
        self._enqueued_at[id(payload)] = time.monotonic()
        self._inbox.put(payload)

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
            "capabilities": sorted(self._capabilities),
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
        self._enqueue(ExecRequest(source=src))

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        if self._trace_enabled:
            self._syscall_log.append(f"call {func}")
        self._logger.debug("call", extra={"func": func})
        self._enqueue(CallRequest(target=func, args=args, kwargs=kwargs))
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

    def cancel(self, timeout: float = 0.2) -> bool:
        """Request cooperative shutdown and wait up to *timeout* seconds."""
        self.mark_stop_reason("cancel_requested")
        self._stop_event.set()
        self._enqueue(StopRequest())
        self.join(timeout)
        return not self.is_alive()

    def kill(self, timeout: float = 0.2) -> bool:
        """Attempt non-cooperative termination for wedged guest code."""
        started = time.monotonic()
        if self.cancel(timeout=timeout):
            self._kill_latency_ms = (time.monotonic() - started) * 1000
            return True
        if self.ident is None:
            return not self.is_alive()
        for _ in range(3):
            result = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(self.ident), ctypes.py_object(_KillRequest)
            )
            if result > 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_ulong(self.ident), None
                )
            self.join(timeout / 3 if timeout > 0 else 0)
            if not self.is_alive():
                self._kill_latency_ms = (time.monotonic() - started) * 1000
                return True
        self._kill_latency_ms = (time.monotonic() - started) * 1000
        return False

    def stop(self, timeout: float = 0.2) -> None:
        if not self.cancel(timeout=timeout):
            self.kill(timeout=timeout)

    def reap(self) -> bool:
        """Drain pending messages after termination."""
        if self.is_alive():
            return False
        while not self._inbox.empty():
            try:
                self._inbox.get_nowait()
            except queue.Empty:
                break
        while not self._outbox.empty():
            try:
                self._outbox.get_nowait()
            except queue.Empty:
                break
        return True

    def quarantine(self, reason: str) -> None:
        self._quarantine_reason = reason
        self.mark_stop_reason(reason)

    def reset(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
        capabilities: Optional[dict[str, Any]] = None,
    ) -> None:
        """Reuse this thread for a new sandbox."""
        old_path = getattr(self, "_cgroup_path", None)
        self.name = name
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self.numa_node = numa_node
        self._bound_numa_node = None
        self.allowed_imports = self._merge_allowed_imports(policy, allowed_imports)
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
        self._capabilities = dict(capabilities or {})
        self._state = "bootstrapped"
        self._start_reason = "recycled"
        self._stop_reason = None
        self._policy_denials = 0
        self._quota_breaches = 0
        self._scheduler_latency = {"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0}
        self._scheduler_latency_sum = 0.0
        self._kill_latency_ms = 0.0
        # Request the sandbox thread to (re)attach itself to the new cgroup.
        # The attachment must happen from the sandbox thread's context.
        self._enqueue(AttachCgroupRequest(old_path=old_path))

    def mark_stop_reason(self, reason: str) -> None:
        if self._stop_reason is None:
            self._stop_reason = reason

    def record_quota_breach(self, reason: str) -> None:
        self._quota_breaches += 1
        self.mark_stop_reason(reason)
        self._logger.warning(
            "quota breach recorded",
            extra={
                "event": "sandbox.quota_breach",
                "cell_id": self.cell_id,
                "sandbox": self.name,
                "reason": reason,
                "quota_breaches": self._quota_breaches,
            },
        )

    @property
    def stats(self):
        cpu_ms = self._cpu_time
        if self._start_time is not None:
            cpu_ms += (time.monotonic() - self._start_time) * 1000
        cost = cpu_ms * 0.0001 + self._mem_peak * 1e-9
        return Stats(
            cell_id=self.cell_id,
            state=self._state,
            start_reason=self._start_reason,
            stop_reason=self._stop_reason,
            cpu_ms=cpu_ms,
            mem_bytes=self._mem_peak,
            mem_hwm_bytes=self._mem_peak,
            latency=dict(self._latency),
            latency_sum=self._latency_sum,
            scheduler_latency_ms=dict(self._scheduler_latency),
            scheduler_latency_ms_sum=self._scheduler_latency_sum,
            kill_latency_ms=self._kill_latency_ms,
            policy_denials=self._policy_denials,
            quota_breaches=self._quota_breaches,
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
            self._state = "running"

            local_vars = {"post": self._outbox.put, "caps": self._capabilities}

            if self.numa_node is not None:
                bind_current_thread(self.numa_node)
            self._bound_numa_node = self.numa_node

            while True:
                payload = self._inbox.get()
                enqueued_at = self._enqueued_at.pop(id(payload), None)
                queued_for_ms = (
                    (time.monotonic() - enqueued_at) * 1000
                    if enqueued_at is not None
                    else 0.0
                )
                self._scheduler_latency_sum += queued_for_ms
                if queued_for_ms <= 0.5:
                    self._scheduler_latency["0.5"] += 1
                elif queued_for_ms <= 1:
                    self._scheduler_latency["1"] += 1
                elif queued_for_ms <= 5:
                    self._scheduler_latency["5"] += 1
                elif queued_for_ms <= 10:
                    self._scheduler_latency["10"] += 1
                else:
                    self._scheduler_latency["inf"] += 1
                if isinstance(payload, StopRequest):
                    self._state = "completed"
                    self.mark_stop_reason("stop_requested")
                    break
                if payload is _STOP:
                    self._state = "completed"
                    self.mark_stop_reason("stop_requested")
                    break
                if isinstance(payload, str):
                    payload = ExecRequest(source=payload)
                if isinstance(payload, AttachCgroupRequest):
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
                    tcp_policy = getattr(self.policy, "tcp", None)
                    if tcp_policy is not None:
                        allowed_tcp = set(tcp_policy)
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
                _thread_local.fs_capability = self._capabilities.get("filesystem")
                _thread_local.net_capability = self._capabilities.get("network")
                _thread_local.subprocess_capability = self._capabilities.get(
                    "subprocess"
                )
                _thread_local.clock_capability = self._capabilities.get("clock")
                _thread_local.random_capability = self._capabilities.get("random")

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
                        if isinstance(payload, CallRequest):
                            importer = builtins_dict["__import__"]
                            try:
                                module_name, func_name = payload.target.rsplit(".", 1)
                            except ValueError as exc:
                                raise errors.SandboxError(
                                    "call target {!r} must include a module path (e.g. 'module.func')".format(
                                        payload.target
                                    )
                                ) from exc
                            mod = importer(module_name, fromlist=["_"])
                            res = object.__getattribute__(mod, func_name)(
                                *payload.args, **payload.kwargs
                            )
                            self._outbox.put(res)
                        elif isinstance(payload, ExecRequest):
                            exec(payload.source, local_vars, local_vars)
                        else:
                            raise errors.SandboxError("unknown request type")
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
                        if isinstance(exc, _KillRequest):
                            self._state = "cancelled"
                            self.mark_stop_reason("killed")
                            break
                        self._errors += 1
                        self._start_time = None
                        if self._on_violation and isinstance(exc, errors.PolicyError):
                            self._policy_denials += 1
                            self.mark_stop_reason("policy_denied")
                            self._on_violation(self.name, exc)
                            self._logger.warning(
                                "policy denied",
                                extra={
                                    "event": "sandbox.policy_denied",
                                    "cell_id": self.cell_id,
                                    "sandbox": self.name,
                                    "reason": str(exc),
                                    "policy_denials": self._policy_denials,
                                },
                            )
                        if isinstance(exc, (errors.CPUExceeded, errors.MemoryExceeded)):
                            reason = (
                                "cpu_quota_exceeded"
                                if isinstance(exc, errors.CPUExceeded)
                                else "memory_quota_exceeded"
                            )
                            self.record_quota_breach(reason)
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
            if self._state == "running":
                self._state = "completed"
            if prev_handler is not None:
                signal.signal(signal.SIGXCPU, prev_handler)
