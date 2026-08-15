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
import logging
import math
import queue
import socket
import struct
import subprocess
import sys
import threading
from typing import Any, Optional

from .. import errors
from ..policy.model import RuntimePolicy
from .protocol import BrokerRequest
from .thread import Stats

logger = logging.getLogger(__name__)

_LEN = struct.Struct("!I")

# Guest results and errors cross the boundary as JSON. Never unpickle data
# produced by untrusted guest code in the supervisor process.
_CHILD_MODULE = "pyisolate.runtime.child"


def _cpu_seconds_from_ms(cpu_ms: Optional[int]) -> Optional[int]:
    """Convert a millisecond CPU budget to the whole seconds ``RLIMIT_CPU`` takes.

    ``RLIMIT_CPU`` has one-second granularity, so a sub-second budget cannot be
    expressed exactly and rounds *up* to one second. Rounding up keeps the limit
    real (the guest is still killed) but weaker than requested, so it is logged
    rather than applied silently -- a quota that quietly differs from the one
    the caller asked for is the failure mode this wiring exists to remove.
    Precise sub-second CPU accounting needs cgroup ``cpu.max``.
    """
    if cpu_ms is None:
        return None
    seconds = max(1, math.ceil(cpu_ms / 1000))
    if cpu_ms < 1000:
        logger.warning(
            "cpu_ms=%d is below RLIMIT_CPU's one-second granularity; the guest "
            "process is limited to %ds of CPU instead. Use wall_time_ms for "
            "finer bounds.",
            cpu_ms,
            seconds,
        )
    return seconds


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

    if isinstance(policy, RuntimePolicy):
        if policy.allow_fs:
            fs = [rule.path for rule in policy.allow_fs]
        if policy.allow_tcp:
            tcp = [rule.destination for rule in policy.allow_tcp]
        return fs, tcp

    # Legacy Policy: ``allow_fs``/``allow_tcp`` are *methods*, not rule
    # collections, so read the plain ``.fs``/``.tcp`` string attributes.
    p_fs = getattr(policy, "fs", None)
    p_tcp = getattr(policy, "tcp", None)
    if p_fs:
        fs = [str(item) for item in p_fs]
    if p_tcp:
        tcp = [str(item) for item in p_tcp]
    return fs, tcp


def _extract_fs_read_write(
    policy: Any,
) -> tuple[Optional[list[str]], Optional[list[str]]]:
    """Split policy filesystem paths into read-only and writable sets.

    Used to build a Landlock ruleset that grants read on read paths and
    read+write on write paths. Handles the compiled ``RuntimePolicy``
    (``allow_fs`` rules with an ``access`` mode) and the legacy ``Policy``
    (``ReadPath``/``WritePath`` capabilities plus ``.fs`` read+write paths).
    """
    if policy is None:
        return None, None

    read: list[str] = []
    write: list[str] = []

    if isinstance(policy, RuntimePolicy):
        for rule in policy.allow_fs:
            if getattr(rule, "access", "readwrite") == "read":
                read.append(rule.path)
            else:
                write.append(rule.path)
        return _dedupe_read_write(read, write)

    for cap in getattr(policy, "capabilities", None) or []:
        path = getattr(cap, "path", None)
        if path is None:
            continue
        if getattr(cap, "kind", None) == "write_path":
            write.append(str(path))
        elif getattr(cap, "kind", None) == "read_path":
            read.append(str(path))
    for item in getattr(policy, "fs", None) or []:
        write.append(str(item))
    return _dedupe_read_write(read, write)


def _dedupe_read_write(
    read: list[str], write: list[str]
) -> tuple[Optional[list[str]], Optional[list[str]]]:
    # A write grant already implies read, so drop any read path that is also
    # writable and de-duplicate each set (order-preserving).
    write_unique = list(dict.fromkeys(write))
    write_set = set(write_unique)
    read_unique = [p for p in dict.fromkeys(read) if p not in write_set]
    return (read_unique or None, write_unique or None)


class ProcessSandbox:
    """Runs guest code in a confined child process behind a JSON channel."""

    def __init__(
        self,
        name: str,
        *,
        policy: Any = None,
        allowed_imports: Optional[list[str]] = None,
        capabilities: Optional[dict[str, Any]] = None,
        backend: str = "process",
        mem_bytes: Optional[int] = None,
        cpu_ms: Optional[int] = None,
        cpu_seconds: Optional[int] = None,
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        confine: bool = True,
        require_seccomp: bool = False,
        require_landlock: bool = False,
    ) -> None:
        self.name = name
        self._backend = backend
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._closed = False
        self._lock = threading.Lock()
        # Wall-clock enforcement. RLIMIT_CPU bounds CPU time in the guest, but a
        # guest that blocks forever burns no CPU, so wall time is enforced here
        # in the supervisor: arm a timer when an operation is dispatched and
        # kill the guest if it has not reported completion in time.
        self.wall_time_ms = wall_time_ms
        self._wall_timer: Optional[threading.Timer] = None
        self._pending_ops = 0
        self._timer_lock = threading.Lock()
        # A dying guest is noticed by two racing observers -- the wall-clock
        # timer and the reader thread seeing EOF -- and a waiter must get
        # exactly one error, the specific one.
        self._termination_lock = threading.Lock()
        self._termination_surfaced = False
        if cpu_seconds is None:
            cpu_seconds = _cpu_seconds_from_ms(cpu_ms)
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
        fs_read, fs_write = _extract_fs_read_write(policy)
        # The child gates broker ``request`` on the granted capability names,
        # mirroring the sub-interpreter backend; only the names cross the
        # boundary, never the capability's secret material.
        capability_names = sorted(capabilities) if capabilities else []

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
                "capabilities": capability_names,
                "fs": fs,
                "tcp": tcp,
                "fs_read": fs_read,
                "fs_write": fs_write,
                "confine": confine,
                "mem_bytes": mem_bytes,
                "cpu_seconds": cpu_seconds,
                "open_files_max": open_files_max,
                "require_seccomp": require_seccomp,
                "require_landlock": require_landlock,
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
            self._surface_termination()

    # -- wall-clock enforcement -------------------------------------------

    def _op_started(self) -> None:
        """Record a dispatched operation and arm the wall-clock timer."""
        if self.wall_time_ms is None:
            return
        with self._timer_lock:
            self._pending_ops += 1
            if self._wall_timer is None:
                self._arm_timer_locked()

    def _op_finished(self) -> None:
        """Clear one completed operation, re-arming while others are pending."""
        if self.wall_time_ms is None:
            return
        with self._timer_lock:
            self._pending_ops = max(0, self._pending_ops - 1)
            self._cancel_timer_locked()
            if self._pending_ops:
                # Operations are pipelined: the guest executes them serially, so
                # the next one starts now and gets its own full budget.
                self._arm_timer_locked()

    def _arm_timer_locked(self) -> None:
        assert self.wall_time_ms is not None
        timer = threading.Timer(self.wall_time_ms / 1000.0, self._on_wall_timeout)
        timer.daemon = True
        self._wall_timer = timer
        timer.start()

    def _cancel_timer_locked(self) -> None:
        if self._wall_timer is not None:
            self._wall_timer.cancel()
            self._wall_timer = None

    def _surface_termination(self) -> None:
        """Hand a waiting ``recv`` exactly one error for an unexpected death.

        The wall-clock timer and the reader thread can both observe the guest
        dying, so the first one here wins and the other is a no-op. A quota
        breach reports its specific error; anything else -- a seccomp kill, a
        segfault -- reports the generic one.
        """
        with self._termination_lock:
            if self._termination_surfaced:
                return
            self._termination_surfaced = True
        if self.termination_reason == "wall_time_exceeded":
            self._outbox.put(errors.WallTimeExceeded())
        else:
            self._outbox.put(
                errors.SandboxError("guest process terminated unexpectedly")
            )

    def _on_wall_timeout(self) -> None:
        """Kill a guest that overran its wall-clock budget and report it."""
        with self._timer_lock:
            self._wall_timer = None
            self._pending_ops = 0
        if not self.is_alive():
            return
        self.termination_reason = "wall_time_exceeded"
        self._errors += 1
        logger.warning(
            "sandbox %s exceeded its %dms wall-clock quota; killing guest",
            self.name,
            self.wall_time_ms,
        )
        # Kill *before* surfacing the error so a caller that catches
        # WallTimeExceeded and immediately inspects the sandbox sees a stopped
        # guest rather than one still burning CPU. ``termination_reason`` is set
        # first so whichever observer gets there reports the quota breach.
        self.kill(timeout=0.2)
        self._surface_termination()

    def _dispatch(self, frame: dict[str, Any]) -> None:
        ev = frame.get("ev")
        if ev == "post":
            self._outbox.put(frame.get("message"))
        elif ev == "error":
            self._errors += 1
            self._op_finished()
            self._outbox.put(self._rebuild_exception(frame))
        elif ev == "done":
            self._op_finished()
        elif ev == "request":
            # A capability-gated broker request from the guest. Surface it as a
            # BrokerRequest via recv(), matching the sub-interpreter backend, so
            # the supervisor mediates the privileged action instead of the guest.
            self._outbox.put(
                BrokerRequest(
                    capability=frame.get("capability", ""),
                    action=frame.get("action", ""),
                    payload=frame.get("payload") or {},
                )
            )
        elif ev == "confinement":
            self.confinement = frame
            self._confined.set()
        # "ready", "log", and "metric" are lifecycle/telemetry frames that do
        # not feed recv(); logging/metrics routing is added with the
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
        self._op_started()
        try:
            self._send({"op": "exec", "source": src})
        except Exception:
            self._op_finished()
            raise

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        self._ops += 1
        self._op_started()
        try:
            self._send(
                {"op": "call", "target": func, "args": list(args), "kwargs": kwargs}
            )
        except Exception:
            self._op_finished()
            raise
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
        with self._timer_lock:
            self._pending_ops = 0
            self._cancel_timer_locked()
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
