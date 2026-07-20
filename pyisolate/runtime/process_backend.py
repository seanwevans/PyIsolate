"""Supervisor-side handle for the ``backend="process"`` isolation mode.

``ProcessSandbox`` launches guest code in a separate OS process
(:mod:`pyisolate.runtime.child`) and speaks the same length-framed JSON
protocol over an inherited ``AF_UNIX`` socketpair.  It duck-types the subset of
the :class:`~pyisolate.runtime.thread.SandboxThread` surface that
:class:`pyisolate.supervisor.Sandbox` delegates to (``exec``, ``call``,
``recv``, ``stop``, ``kill``, ``cancel``, ``reap``, ``is_alive``, ``name``),
so the existing handle wrapper works unchanged.

Unlike the sub-interpreter backend, the boundary here is a real process
boundary: guest code runs in a distinct address space and cannot read or
corrupt supervisor memory.  Kernel-level confinement of that process
(no-new-privs, seccomp, rlimits, Landlock, cgroups) is layered on in follow-up
work; this module establishes the process boundary and transport.
"""

from __future__ import annotations

import json
import queue
import socket
import struct
import subprocess
import sys
import threading
from typing import Any, Optional

from .. import errors
from .thread import Stats

_LEN = struct.Struct("!I")

# Guest results and errors cross the boundary as JSON. Never unpickle data
# produced by untrusted guest code in the supervisor process.
_CHILD_MODULE = "pyisolate.runtime.child"


def _extract_fs_tcp(policy: Any) -> tuple[Optional[list[str]], Optional[list[str]]]:
    """Best-effort extraction of filesystem/TCP allow-lists from a policy.

    Handles both the legacy :class:`~pyisolate.policy.Policy` shape (``.fs`` /
    ``.tcp`` string collections) and the compiled
    :class:`~pyisolate.policy.model.RuntimePolicy` shape (``allow_fs`` /
    ``allow_tcp`` rule objects). Anything richer is left to the kernel
    enforcement layers.
    """

    if policy is None:
        return None, None

    fs: Optional[list[str]] = None
    tcp: Optional[list[str]] = None

    allow_fs = getattr(policy, "allow_fs", None)
    allow_tcp = getattr(policy, "allow_tcp", None)
    if allow_fs is not None or allow_tcp is not None:
        if allow_fs:
            fs = [rule.path for rule in allow_fs]
        if allow_tcp:
            tcp = [rule.destination for rule in allow_tcp]
        return fs, tcp

    p_fs = getattr(policy, "fs", None)
    p_tcp = getattr(policy, "tcp", None)
    if p_fs:
        fs = [str(item) for item in p_fs]
    if p_tcp:
        tcp = [str(item) for item in p_tcp]
    return fs, tcp


class ProcessSandbox:
    """Runs guest code in a confined child process behind a JSON channel."""

    def __init__(
        self,
        name: str,
        *,
        policy: Any = None,
        allowed_imports: Optional[list[str]] = None,
        backend: str = "process",
        mem_bytes: Optional[int] = None,
        cpu_seconds: Optional[int] = None,
        confine: bool = True,
        require_seccomp: bool = False,
    ) -> None:
        self.name = name
        self._backend = backend
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._closed = False
        self._lock = threading.Lock()
        # Tenant-quota bookkeeping mirrors SandboxThread so the supervisor's
        # shared reservation helpers can account for process sandboxes too.
        self._tenant: Optional[str] = None
        self._tenant_quota: Optional[int] = None
        self._tenant_quota_reserved = False
        # Handle-surface attributes the Sandbox wrapper reads. Features not yet
        # implemented for this backend (see the methods below) are surfaced as
        # explicit NotImplementedError rather than AttributeError.
        self._cgroup_path = None
        self.quota_enforcement = None
        self.termination_reason: Optional[str] = None
        self._quarantine_reason: Optional[str] = None
        self._ops = 0
        self._errors = 0
        # Populated from the child's "confinement" frame during startup.
        self.confinement: Optional[dict[str, Any]] = None
        self._confined = threading.Event()

        fs, tcp = _extract_fs_tcp(policy)

        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-m", _CHILD_MODULE, str(child_sock.fileno())],
                pass_fds=(child_sock.fileno(),),
                close_fds=True,
            )
        except Exception:
            parent_sock.close()
            child_sock.close()
            raise
        # The child holds its own copy of the socketpair end; drop ours so an
        # unexpected child exit surfaces as EOF on the parent side.
        child_sock.close()
        self._sock = parent_sock

        self._send(
            {
                "op": "bootstrap",
                "name": name,
                "allowed_imports": allowed_imports,
                "fs": fs,
                "tcp": tcp,
                "confine": confine,
                "mem_bytes": mem_bytes,
                "cpu_seconds": cpu_seconds,
                "require_seccomp": require_seccomp,
            }
        )

        self._reader = threading.Thread(
            target=self._read_loop, name=f"pyisolate-proc-{name}", daemon=True
        )
        self._reader.start()
        if not confine:
            self._confined.set()

    # -- transport ---------------------------------------------------------

    def _send(self, obj: dict[str, Any]) -> None:
        data = json.dumps(obj).encode("utf-8")
        with self._lock:
            if self._closed:
                raise errors.SandboxError("sandbox process channel is closed")
            self._sock.sendall(_LEN.pack(len(data)) + data)

    def _recv_exact(self, size: int) -> bytes | None:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            try:
                chunk = self._sock.recv(remaining)
            except OSError:
                return None
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_loop(self) -> None:
        while True:
            header = self._recv_exact(_LEN.size)
            if header is None:
                break
            (length,) = _LEN.unpack(header)
            body = self._recv_exact(length)
            if body is None:
                break
            try:
                frame = json.loads(body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            self._dispatch(frame)
        # The channel closed. If this was not a caller-initiated stop, the guest
        # process died on its own -- e.g. a seccomp-denied syscall killed it --
        # so surface that to any waiter instead of letting recv() hang to
        # timeout.
        if not self._closed:
            self._closed = True
            self._confined.set()
            self._outbox.put(
                errors.SandboxError("guest process terminated unexpectedly")
            )

    def _dispatch(self, frame: dict[str, Any]) -> None:
        ev = frame.get("ev")
        if ev == "post":
            self._outbox.put(frame.get("message"))
        elif ev == "error":
            self._errors += 1
            self._outbox.put(self._rebuild_exception(frame))
        elif ev == "confinement":
            self.confinement = frame
            self._confined.set()
        # "ready", "done", "log", and "metric" are lifecycle/telemetry frames
        # that do not feed recv(); logging/metrics routing is added with the
        # observability wiring for this backend.

    @staticmethod
    def _rebuild_exception(frame: dict[str, Any]) -> Exception:
        # Reconstruct a known pyisolate error by name so callers can still do
        # ``pytest.raises(iso.PolicyError)``. Never eval arbitrary type names.
        exc_type = frame.get("exc_type", "SandboxError")
        message = frame.get("message", "")
        cls = getattr(errors, exc_type, None)
        if isinstance(cls, type) and issubclass(cls, Exception):
            return cls(message)
        return errors.SandboxError(f"{exc_type}: {message}")

    def wait_confined(self, timeout: float | None = None) -> Optional[dict[str, Any]]:
        """Block until the child reports its confinement, returning the report."""
        self._confined.wait(timeout)
        return self.confinement

    # -- cell ABI ----------------------------------------------------------

    def exec(self, src: str) -> None:
        self._ops += 1
        self._send({"op": "exec", "source": src})

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        self._ops += 1
        self._send({"op": "call", "target": func, "args": list(args), "kwargs": kwargs})
        try:
            return self.recv(timeout)
        except errors.SandboxError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise errors.SandboxError(str(exc)) from exc

    def recv(self, timeout: Optional[float] = None):
        try:
            result = self._outbox.get(timeout=timeout)
        except queue.Empty:
            raise errors.TimeoutError("no message received")
        if isinstance(result, Exception):
            raise result
        return result

    # -- lifecycle ---------------------------------------------------------

    def is_alive(self) -> bool:
        return self._proc.poll() is None

    @property
    def returncode(self) -> Optional[int]:
        """Child exit status: ``None`` if running, else exit code or ``-signal``.

        A guest killed by its seccomp filter reports ``-signal.SIGSYS``.
        """
        return self._proc.poll()

    def cancel(self, timeout: float = 0.2) -> bool:
        with self._lock:
            if not self._closed:
                try:
                    data = json.dumps({"op": "stop"}).encode("utf-8")
                    self._sock.sendall(_LEN.pack(len(data)) + data)
                except OSError:
                    pass
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        return not self.is_alive()

    def kill(self, timeout: float = 0.2) -> bool:
        if self.cancel(timeout=timeout):
            self._teardown()
            return True
        self._proc.terminate()
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
        self._teardown()
        return not self.is_alive()

    def stop(self, timeout: float = 0.2) -> None:
        self.kill(timeout=timeout)

    def reap(self) -> bool:
        if self.is_alive():
            return False
        self._teardown()
        return True

    def _teardown(self) -> None:
        with self._lock:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    def quarantine(self, reason: str) -> None:
        self._quarantine_reason = reason
        self.kill(timeout=0.2)

    # -- telemetry ---------------------------------------------------------

    def get_denial_events(self) -> list[dict[str, str]]:
        # Denial telemetry for the process backend is delivered by the kernel
        # enforcement layers added in follow-up work; none is collected yet.
        return []

    def get_syscall_log(self) -> list[str]:
        return []

    @property
    def stats(self) -> Stats:
        # CPU/memory accounting for the process backend arrives with the rlimit
        # and cgroup layers; operations and errors are tracked here already.
        return Stats(
            cpu_ms=0.0,
            mem_bytes=0,
            latency={"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0},
            latency_sum=0.0,
            errors=self._errors,
            operations=self._ops,
            cost=0.0,
            denials=[],
        )

    def profile(self) -> Stats:
        return self.stats

    # -- not-yet-supported handle surface ----------------------------------

    def enable_tracing(self) -> None:
        raise NotImplementedError(
            "operation tracing is not supported for the process backend yet"
        )

    def snapshot(self) -> dict:
        raise NotImplementedError(
            "checkpointing is not supported for the process backend yet"
        )

    def reset_config(self) -> dict:
        raise NotImplementedError(
            "reset/recycle is not supported for the process backend yet"
        )

    def reset(self, *args: Any, **kwargs: Any) -> None:
        raise NotImplementedError(
            "reset/recycle is not supported for the process backend yet"
        )
