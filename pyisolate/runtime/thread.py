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
import sys
import threading
import time
import tracemalloc
import types
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .. import errors
from ..capabilities import (
    ClockCapability,
    FilesystemCapability,
    NetworkCapability,
    RandomCapability,
    SecretCapability,
    SubprocessCapability,
)
from .protocol import (
    AttachCgroupRequest,
    CallRequest,
    ExecRequest,
    StopRequest,
)
from ..numa import bind_current_thread
from ..observability.trace import Tracer

_thread_local = threading.local()

_ORIG_OPEN = builtins.open
_ORIG_SOCKET_CONNECT = socket.socket.connect
_ORIG_THREAD_START = threading.Thread.start
_CAPABILITY_MARKER = "__pyisolate_capability__"


def _serialize_capability(capability: Any) -> Any:
    if isinstance(capability, FilesystemCapability):
        return {
            _CAPABILITY_MARKER: "filesystem",
            "roots": [str(root) for root in capability.roots],
        }
    if isinstance(capability, NetworkCapability):
        return {
            _CAPABILITY_MARKER: "network",
            "destinations": sorted(capability.destinations),
        }
    if isinstance(capability, SecretCapability):
        return {
            _CAPABILITY_MARKER: "secrets",
            "values": {
                key: value.hex() for key, value in sorted(capability.values.items())
            },
        }
    if isinstance(capability, SubprocessCapability):
        return {
            _CAPABILITY_MARKER: "subprocess",
            "allowed_commands": sorted(capability.allowed_commands),
            "allow_shell": capability.allow_shell,
        }
    if isinstance(capability, ClockCapability):
        return {_CAPABILITY_MARKER: "clock"}
    if isinstance(capability, RandomCapability):
        return {_CAPABILITY_MARKER: "random"}
    return capability


def _deserialize_capability(capability: Any) -> Any:
    if not isinstance(capability, dict):
        return capability
    kind = capability.get(_CAPABILITY_MARKER)
    if kind == "filesystem":
        roots = capability.get("roots", [])
        return FilesystemCapability.from_paths(*roots)
    if kind == "network":
        destinations = capability.get("destinations", [])
        return NetworkCapability.from_destinations(*destinations)
    if kind == "secrets":
        encoded_values = capability.get("values", {})
        decoded_values = {
            key: bytes.fromhex(value) for key, value in encoded_values.items()
        }
        return SecretCapability(values=decoded_values)
    if kind == "subprocess":
        commands = capability.get("allowed_commands", [])
        allow_shell = bool(capability.get("allow_shell", False))
        return SubprocessCapability.from_commands(*commands, allow_shell=allow_shell)
    if kind == "clock":
        return ClockCapability()
    if kind == "random":
        return RandomCapability()
    return capability


def serialize_capabilities(capabilities: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not capabilities:
        return {}
    return {
        name: _serialize_capability(capability)
        for name, capability in sorted(capabilities.items())
    }


def deserialize_capabilities(capabilities: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not capabilities:
        return {}
    return {
        name: _deserialize_capability(capability)
        for name, capability in capabilities.items()
    }


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

    sandbox = getattr(_thread_local, "sandbox", None)
    if sandbox is not None:
        sandbox._check_open_files_quota()
    opened = _ORIG_OPEN(file, *args, **kwargs)
    if sandbox is None:
        return opened
    sandbox._open_files += 1

    def _release():
        sandbox._open_files = max(0, sandbox._open_files - 1)

    weakref.finalize(opened, _release)
    return opened


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
    sandbox = getattr(_thread_local, "sandbox", None)
    if sandbox is not None:
        sandbox._network_ops += 1
        if (
            sandbox.network_ops_max is not None
            and sandbox._network_ops > sandbox.network_ops_max
        ):
            raise errors.NetworkExceeded()
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


def _make_sandbox_thread_class(sandbox: "SandboxThread"):
    class SandboxedThread(threading.Thread):
        def start(self, *args, **kwargs):
            sandbox._check_child_work_quota()
            original_run = self.run

            def _run_with_accounting(*r_args, **r_kwargs):
                try:
                    return original_run(*r_args, **r_kwargs)
                finally:
                    sandbox._child_work = max(0, sandbox._child_work - 1)

            self.run = _run_with_accounting  # type: ignore[assignment]
            sandbox._child_work += 1
            try:
                return _ORIG_THREAD_START(self, *args, **kwargs)
            except Exception:
                sandbox._child_work = max(0, sandbox._child_work - 1)
                raise

    return SandboxedThread


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
    if base == "threading":
        sandbox = getattr(_thread_local, "sandbox", None)
        if sandbox is None:
            return module
        mod = types.ModuleType("threading", module.__doc__)
        mod.__dict__.update({k: getattr(threading, k) for k in dir(threading)})
        mod.Thread = _make_sandbox_thread_class(sandbox)
        return mod
    if base == "pathlib":
        mod = types.ModuleType("pathlib", module.__doc__)
        mod.__dict__.update({k: getattr(module, k) for k in dir(module)})

        class SandboxedPath(type(module.Path())):
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
    cpu_ms: float
    mem_bytes: int
    latency: dict[str, int]
    latency_sum: float
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
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        network_ops_max: Optional[int] = None,
        output_bytes_max: Optional[int] = None,
        child_work_max: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        on_violation: Optional[Callable[[str, Exception], None]] = None,
        tracer: Optional["Tracer"] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
        capabilities: Optional[dict[str, Any]] = None,
    ):
        super().__init__(name=name, daemon=True)
        self._logger = logging.getLogger(f"pyisolate.{name}")
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self.policy = policy
        self.cpu_quota_ms = cpu_ms
        self.mem_quota_bytes = mem_bytes
        self.wall_time_ms = wall_time_ms
        self.open_files_max = open_files_max
        self.network_ops_max = network_ops_max
        self.output_bytes_max = output_bytes_max
        self.child_work_max = child_work_max
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
        self._capabilities = deserialize_capabilities(capabilities)
        self._quarantine_reason: str | None = None
        self.termination_reason: str | None = None
        self._open_files = 0
        self._network_ops = 0
        self._output_bytes = 0
        self._child_work = 0
        self._next_attach_msg_id = 1
        self._seen_attach_msg_ids: set[int] = set()

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
            "capabilities": serialize_capabilities(self._capabilities),
            "wall_time_ms": self.wall_time_ms,
            "open_files_max": self.open_files_max,
            "network_ops_max": self.network_ops_max,
            "output_bytes_max": self.output_bytes_max,
            "child_work_max": self.child_work_max,
        }

    @staticmethod
    def _estimate_output_size(item: Any) -> int:
        if isinstance(item, bytes):
            return len(item)
        if isinstance(item, str):
            return len(item.encode("utf-8"))
        return len(repr(item).encode("utf-8"))

    def _post(self, item: Any) -> None:
        self._output_bytes += self._estimate_output_size(item)
        if self.output_bytes_max is not None and self._output_bytes > self.output_bytes_max:
            raise errors.OutputExceeded()
        self._outbox.put(item)

    def _check_open_files_quota(self) -> None:
        if self.open_files_max is not None and self._open_files >= self.open_files_max:
            raise errors.OpenFilesExceeded()

    def _check_child_work_quota(self) -> None:
        if self.child_work_max is not None and self._child_work >= self.child_work_max:
            raise errors.ChildWorkExceeded()

    def _trace_guard(self, frame, event, arg):
        if self.wall_time_ms is None:
            return self._trace_guard
        if self._start_time is None:
            return self._trace_guard
        elapsed_ms = (time.monotonic() - self._start_time) * 1000
        if elapsed_ms > self.wall_time_ms:
            raise errors.WallTimeExceeded()
        return self._trace_guard

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
        self._inbox.put(ExecRequest(source=src))

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        if self._trace_enabled:
            self._syscall_log.append(f"call {func}")
        self._logger.debug("call", extra={"func": func})
        self._inbox.put(CallRequest(target=func, args=args, kwargs=kwargs))
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
        self._stop_event.set()
        self._inbox.put(StopRequest())
        self.join(timeout)
        return not self.is_alive()

    def kill(self, timeout: float = 0.2) -> bool:
        """Attempt non-cooperative termination for wedged guest code."""
        if self.cancel(timeout=timeout):
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
                return True
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

    def reset(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        network_ops_max: Optional[int] = None,
        output_bytes_max: Optional[int] = None,
        child_work_max: Optional[int] = None,
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
        self.wall_time_ms = wall_time_ms
        self.open_files_max = open_files_max
        self.network_ops_max = network_ops_max
        self.output_bytes_max = output_bytes_max
        self.child_work_max = child_work_max
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
        self._capabilities = deserialize_capabilities(capabilities)
        self.termination_reason = None
        self._open_files = 0
        self._network_ops = 0
        self._output_bytes = 0
        self._child_work = 0
        # Request the sandbox thread to (re)attach itself to the new cgroup.
        # The attachment must happen from the sandbox thread's context.
        msg_id = self._next_attach_msg_id
        self._next_attach_msg_id += 1
        self._inbox.put(AttachCgroupRequest(old_path=old_path, msg_id=msg_id))

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

            local_vars = {"post": self._post, "caps": self._capabilities}

            if self.numa_node is not None:
                bind_current_thread(self.numa_node)
            self._bound_numa_node = self.numa_node

            while True:
                payload = self._inbox.get()
                if payload is _STOP:
                    break
                if isinstance(payload, StopRequest):
                    break
                if isinstance(payload, AttachCgroupRequest):
                    if payload.msg_id in self._seen_attach_msg_ids:
                        continue
                    self._seen_attach_msg_ids.add(payload.msg_id)
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
                if isinstance(payload, str):
                    payload = ExecRequest(source=payload)

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
                _thread_local.sandbox = self

                builtins_dict = _SAFE_BUILTINS.copy()
                builtins_dict["open"] = _blocked_open
                builtins_dict["__import__"] = _make_importer(self.allowed_imports)
                local_vars["__builtins__"] = builtins_dict

                self._ops += 1
                op_start = time.monotonic()
                with self._tracer.start_span(f"sandbox:{self.name}"):
                    sys_trace_before = sys.gettrace()
                    try:
                        start_cpu = time.thread_time()
                        self._start_time = time.monotonic()
                        sys.settrace(self._trace_guard)
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
                            self._post(res)
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
                            break
                        self._errors += 1
                        self._start_time = None
                        if isinstance(exc, errors.WallTimeExceeded):
                            self.termination_reason = "wall_time_exceeded"
                        elif isinstance(exc, errors.OpenFilesExceeded):
                            self.termination_reason = "open_files_exceeded"
                        elif isinstance(exc, errors.NetworkExceeded):
                            self.termination_reason = "network_exceeded"
                        elif isinstance(exc, errors.OutputExceeded):
                            self.termination_reason = "output_exceeded"
                        elif isinstance(exc, errors.ChildWorkExceeded):
                            self.termination_reason = "child_work_exceeded"
                        elif isinstance(exc, errors.CPUExceeded):
                            self.termination_reason = "cpu_exceeded"
                        elif isinstance(exc, errors.MemoryExceeded):
                            self.termination_reason = "memory_exceeded"
                        if self._on_violation and isinstance(exc, errors.PolicyError):
                            self._on_violation(self.name, exc)
                        self._outbox.put(exc)
                    finally:
                        sys.settrace(sys_trace_before)
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
