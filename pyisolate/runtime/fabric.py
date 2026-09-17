"""The fabric: sub-interpreter cells inside worker processes that can be killed.

:mod:`pyisolate.runtime.subinterpreter` gives cheap, namespace-isolated cells,
but leaves one thing unsolved that a multi-tenant deployment cannot live
without: **a running cell cannot be reclaimed.** ``close()`` refuses while the
guest executes, there is no ``kill``, and an async exception aimed at the thread
does not reach the interpreter running in it. In-process, a runaway guest is
permanent -- the cell is abandoned and its thread stays pinned for the life of
the process.

The fabric fixes that by putting the cells somewhere killable:

    Supervisor
      |
      +-- Worker process  <- the kill domain
      |     +-- cell  cell  cell        (one CellPool, many cells)
      |
      +-- Worker process
            +-- cell  cell

Three levels, and each one is a different kind of boundary:

* a **cell** separates namespaces -- its own ``sys.modules``, its own
  ``builtins``, its own globals. Not a boundary against hostile Python.
* a **worker** is the unit that gets killed and replaced, so it bounds the
  damage a runaway or wedged guest can do. It is also where a memory cap can
  actually be enforced, because ``sys.getallocatedblocks()`` is process-global
  rather than per-interpreter, so there is no per-cell figure to limit.
* the **fabric** decides which worker a tenant's cells land in, which is how a
  deployment chooses its blast radius.

Placement is the part worth getting right. With ``tenant_isolation=True`` (the
default) a worker only ever hosts one tenant's cells, so killing it for a
runaway costs that tenant and nobody else. Turning it off packs tenants together
for density and makes them share a fate; that is a real trade and the fabric
makes callers state which one they want rather than picking silently.

This is still not a boundary against hostile Python -- a guest that escapes its
cell owns its worker, and the worker is an ordinary process with the
supervisor's privileges. For untrusted code use ``backend="process"``, one
sandbox per process, or a microVM. What the fabric buys is that trusted-but-
independent tenants cannot wedge each other, and that a tenant which does wedge
itself is recoverable.
"""

from __future__ import annotations

import errno
import itertools
import json
import logging
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .. import errors
from . import subinterpreter
from .process_backend import build_child_env

logger = logging.getLogger(__name__)

_LEN = struct.Struct("!I")
_WORKER_MODULE = "pyisolate.runtime.cell_worker"

#: How long to wait for a worker to report ``ready`` before treating the spawn
#: as failed. Generous: the worker imports pyisolate and builds a pool first.
_READY_TIMEOUT = 30.0

#: How long a SIGTERM gets before SIGKILL when retiring a worker cleanly. A
#: worker with a stranded cell never exits on its own, so this stays short.
_TERM_GRACE = 0.5


class WorkerDied(errors.SandboxError):
    """The worker hosting this cell went away, taking the cell with it."""


@dataclass
class FabricStats:
    """Counters that make placement and recycling legible in production."""

    workers_started: int = 0
    workers_killed: int = 0
    workers_died: int = 0
    cells_opened: int = 0
    cells_closed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "workers_started": self.workers_started,
            "workers_killed": self.workers_killed,
            "workers_died": self.workers_died,
            "cells_opened": self.cells_opened,
            "cells_closed": self.cells_closed,
        }


@dataclass
class _Pending:
    """One in-flight operation, waiting on its worker."""

    done: threading.Event = field(default_factory=threading.Event)
    error: Optional[tuple[str, str]] = None
    messages: list[tuple[str, Any]] = field(default_factory=list)


class Worker:
    """One worker process, its channel, and the cells currently open in it."""

    _ids = itertools.count(1)

    def __init__(
        self,
        *,
        tenant: Optional[str] = None,
        warm_per_spec: int = 1,
        max_warm: int = 32,
        mem_bytes: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
    ) -> None:
        self.id = next(self._ids)
        self.tenant = tenant
        self.started_at = time.monotonic()
        self.dead_reason: Optional[str] = None
        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._closed = False
        self._seq = itertools.count(1)
        # Keyed by operation sequence number for exec/call, and by a string for
        # the one-shot lifecycle replies ("opened:<cell>", "closed:<cell>",
        # "stats") -- those have no sequence of their own because the worker
        # answers them with a named event rather than a numbered completion.
        self._pending: dict[object, _Pending] = {}
        self._cell_inbox: dict[str, list[tuple[str, Any]]] = {}
        self._ready = threading.Event()
        self._ready_info: dict[str, Any] = {}
        # Set the moment the channel reports EOF, before the process is reaped.
        # ``Popen.poll()`` returns None when it cannot take the waitpid lock, so
        # while the reader thread is inside ``wait()`` a dead worker would
        # otherwise still look alive -- long enough for placement to hand it a
        # new cell.
        self._eof = threading.Event()

        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._proc = subprocess.Popen(
                [sys.executable, "-m", _WORKER_MODULE, str(child_sock.fileno())],
                pass_fds=(child_sock.fileno(),),
                close_fds=True,
                env=build_child_env(env),
            )
        except Exception:
            parent_sock.close()
            child_sock.close()
            raise
        # Drop our copy of the child's end so an unexpected worker exit shows up
        # as EOF on the parent side rather than hanging the reader forever.
        child_sock.close()
        self._sock = parent_sock

        self._reader = threading.Thread(
            target=self._read_loop, name=f"pyisolate-worker-{self.id}", daemon=True
        )
        self._reader.start()
        self._send(
            {
                "op": "hello",
                "warm_per_spec": warm_per_spec,
                "max_warm": max_warm,
                "mem_bytes": mem_bytes,
            }
        )
        if not self._ready.wait(_READY_TIMEOUT):
            self.kill("worker did not become ready")
            raise errors.SandboxError(
                f"fabric worker {self.id} did not report ready within "
                f"{_READY_TIMEOUT}s"
            )

    # --- introspection ---

    @property
    def pid(self) -> Optional[int]:
        return self._proc.pid

    @property
    def info(self) -> dict[str, Any]:
        return dict(self._ready_info)

    def is_alive(self) -> bool:
        if self._closed or self._eof.is_set():
            return False
        return self._proc.poll() is None

    def cell_count(self) -> int:
        with self._lock:
            return len(self._cell_inbox)

    # --- transport ---

    def _send(self, obj: dict[str, Any]) -> None:
        data = json.dumps(obj).encode("utf-8")
        with self._send_lock:
            if self._closed:
                raise WorkerDied(f"fabric worker {self.id} is closed")
            try:
                self._sock.sendall(_LEN.pack(len(data)) + data)
            except OSError as exc:
                raise WorkerDied(
                    f"fabric worker {self.id} channel is gone: {exc}"
                ) from exc

    def _recv_exact(self, size: int) -> Optional[bytes]:
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
            (size,) = _LEN.unpack(header)
            body = self._recv_exact(size)
            if body is None:
                break
            try:
                frame = json.loads(body.decode("utf-8"))
            except ValueError:
                logger.warning("worker %s sent an unparseable frame", self.id)
                continue
            try:
                self._dispatch(frame)
            except Exception:  # pragma: no cover - never lose the reader
                logger.exception("worker %s frame dispatch failed", self.id)
        # EOF: the worker exited, was killed, or crashed. Mark it unusable
        # first, so placement stops considering it before we block on the reap.
        self._eof.set()
        # Reap it here rather than waiting for the next placement decision to
        # poll. A killed child stays a zombie until someone waits on it, and a
        # fabric that recycles workers under load would accumulate one per
        # recycle. The channel closing is the earliest reliable signal that the
        # process is finished, so it is the right place to collect it.
        try:
            self._proc.wait(timeout=_TERM_GRACE)
        except subprocess.TimeoutExpired:  # pragma: no cover - EOF without exit
            logger.warning("worker %s closed its channel but is still running", self.id)
        # Everything waiting on it has to be told, or callers block forever on a
        # process that is gone.
        self._fail_all(self.dead_reason or "worker process exited")

    def _dispatch(self, frame: dict[str, Any]) -> None:
        event = frame.get("ev")
        if event == "ready":
            self._ready_info = {k: v for k, v in frame.items() if k not in ("ev",)}
            self._ready.set()
            return
        if event == "stats":
            self._resolve_stats(frame)
            return

        cell_id = frame.get("cell")
        if event in ("post", "log", "metric", "request"):
            if cell_id is not None:
                with self._lock:
                    self._cell_inbox.setdefault(cell_id, []).append(
                        (event, frame.get("payload"))
                    )
            return
        if event in ("opened", "closed"):
            self._resolve_lifecycle(event, frame)
            return
        if event in ("done", "error"):
            seq = frame.get("seq")
            with self._lock:
                pending = self._pending.pop(seq, None) if seq is not None else None
            if pending is None:
                # An error with no sequence is a worker-level failure (a failed
                # memory cap, an unknown op). Nothing is waiting on it, so log
                # it rather than dropping it silently.
                if event == "error":
                    logger.warning(
                        "worker %s error: %s: %s",
                        self.id,
                        frame.get("exc_type"),
                        frame.get("message"),
                    )
                return
            if event == "error":
                pending.error = (
                    str(frame.get("exc_type", "SandboxError")),
                    str(frame.get("message", "")),
                )
            pending.done.set()

    def _resolve_lifecycle(self, event: str, frame: dict[str, Any]) -> None:
        key = f"{event}:{frame.get('cell')}"
        with self._lock:
            pending = self._pending.pop(key, None)
        if pending is not None:
            pending.messages.append((event, frame))
            pending.done.set()

    def _resolve_stats(self, frame: dict[str, Any]) -> None:
        with self._lock:
            pending = self._pending.pop("stats", None)
        if pending is not None:
            pending.messages.append(("stats", frame))
            pending.done.set()

    def _fail_all(self, reason: str) -> None:
        with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()
            self._closed = True
        for item in pending:
            if item.error is None:
                item.error = ("WorkerDied", reason)
            item.done.set()

    def _await(self, key: Any, timeout: Optional[float]) -> _Pending:
        pending = _Pending()
        with self._lock:
            if self._closed:
                raise WorkerDied(f"fabric worker {self.id} is closed")
            self._pending[key] = pending
        return pending

    # --- operations ---

    def open_cell(
        self,
        cell_id: str,
        *,
        allowed_imports: Optional[list[str]] = None,
        preimport: Optional[list[str]] = None,
        timeout: Optional[float] = _READY_TIMEOUT,
    ) -> dict[str, Any]:
        pending = self._await(f"opened:{cell_id}", timeout)
        self._send(
            {
                "op": "open",
                "cell": cell_id,
                "allowed_imports": list(allowed_imports or []),
                "preimport": None if preimport is None else list(preimport),
            }
        )
        self._wait(pending, timeout, f"opening cell {cell_id}")
        with self._lock:
            self._cell_inbox.setdefault(cell_id, [])
        return pending.messages[0][1] if pending.messages else {}

    def run(
        self,
        cell_id: str,
        frame: dict[str, Any],
        *,
        timeout: Optional[float],
    ) -> None:
        """Dispatch one operation and wait for the worker to report on it.

        A timeout here is not "the call was slow" -- it means the guest never
        came back, and nothing short of killing the worker will change that.
        The caller (``WorkerPool.run``) is what turns that into a recycle.
        """
        seq = next(self._seq)
        pending = self._await(seq, timeout)
        payload = dict(frame)
        payload["cell"] = cell_id
        payload["seq"] = seq
        self._send(payload)
        self._wait(pending, timeout, f"cell {cell_id} operation")

    def stats(self, timeout: float = 5.0) -> dict[str, Any]:
        pending = self._await("stats", timeout)
        self._send({"op": "stats"})
        self._wait(pending, timeout, "worker stats")
        return pending.messages[0][1] if pending.messages else {}

    def close_cell(self, cell_id: str, timeout: float = 5.0) -> None:
        try:
            pending = self._await(f"closed:{cell_id}", timeout)
            self._send({"op": "close", "cell": cell_id})
            self._wait(pending, timeout, f"closing cell {cell_id}")
        except WorkerDied:
            # Closing a cell in a worker that is already gone is a no-op, not
            # an error: the kill freed it.
            pass
        finally:
            with self._lock:
                self._cell_inbox.pop(cell_id, None)

    def drain(self, cell_id: str) -> list[tuple[str, Any]]:
        with self._lock:
            messages = self._cell_inbox.get(cell_id) or []
            self._cell_inbox[cell_id] = []
        return messages

    def _wait(self, pending: _Pending, timeout: Optional[float], what: str) -> None:
        if not pending.done.wait(timeout):
            raise TimeoutError(f"{what} did not complete within {timeout}s")
        if pending.error is not None:
            exc_type, message = pending.error
            if exc_type == "WorkerDied":
                raise WorkerDied(message)
            raise _rebuild(exc_type, message)

    # --- teardown ---

    def kill(self, reason: str) -> None:
        """SIGKILL the worker. The only reclaim that works on a stranded cell."""
        self.dead_reason = reason
        if self._proc.poll() is None:
            try:
                self._proc.kill()
            except OSError as exc:  # pragma: no cover - already reaped
                if exc.errno != errno.ESRCH:
                    raise
        self._reap()

    def stop(self, timeout: float = _TERM_GRACE) -> None:
        """Ask the worker to exit, then kill it if it will not.

        A worker holding a stranded cell can never exit on its own, so the
        escalation is not a fallback for slow shutdown -- it is the expected
        path whenever a guest is still running.
        """
        if self._proc.poll() is None:
            try:
                self._send({"op": "stop"})
            except (WorkerDied, OSError):
                pass
            try:
                self._proc.wait(timeout)
            except subprocess.TimeoutExpired:
                self.kill("worker did not stop on request")
                return
        self._reap()

    def _reap(self) -> None:
        try:
            self._proc.wait(timeout=_TERM_GRACE)
        except subprocess.TimeoutExpired:  # pragma: no cover - SIGKILL is prompt
            logger.warning("worker %s did not reap", self.id)
        self._fail_all(self.dead_reason or "worker stopped")
        try:
            self._sock.close()
        except OSError:
            pass

    @property
    def returncode(self) -> Optional[int]:
        return self._proc.poll()


def _rebuild(exc_type: str, message: str) -> BaseException:
    """Recreate a worker-side exception by name, without importing anything.

    Only the name crosses the boundary, so this maps the names the runtime is
    known to produce and falls back to SandboxError. It never looks the name up
    dynamically: that would let a worker name any class in the supervisor.
    """
    known: dict[str, type[BaseException]] = {
        "SandboxError": errors.SandboxError,
        "PolicyError": errors.PolicyError,
        "TimeoutError": errors.TimeoutError,
        "WallTimeExceeded": errors.WallTimeExceeded,
        "MemoryExceeded": errors.MemoryExceeded,
        "ValueError": ValueError,
        "TypeError": TypeError,
        "ImportError": ImportError,
        "NameError": NameError,
        "AttributeError": AttributeError,
        "ZeroDivisionError": ZeroDivisionError,
    }
    cls = known.get(exc_type, errors.SandboxError)
    return cls(f"{exc_type}: {message}" if cls is errors.SandboxError else message)


class WorkerPool:
    """Places cells into worker processes and recycles workers that wedge."""

    def __init__(
        self,
        *,
        max_workers: int = 4,
        cells_per_worker: int = 8,
        tenant_isolation: bool = True,
        warm_per_spec: int = 1,
        max_warm: int = 32,
        worker_mem_bytes: Optional[int] = None,
        env: Optional[dict[str, str]] = None,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        if cells_per_worker < 1:
            raise ValueError("cells_per_worker must be >= 1")
        self.max_workers = max_workers
        self.cells_per_worker = cells_per_worker
        self.tenant_isolation = tenant_isolation
        self._warm_per_spec = warm_per_spec
        self._max_warm = max_warm
        self._worker_mem_bytes = worker_mem_bytes
        self._env = env
        self._workers: list[Worker] = []
        self._lock = threading.Lock()
        self._stats = FabricStats()
        self._closed = False
        self._cell_ids = itertools.count(1)

    # --- placement ---

    def placement_for(self, tenant: Optional[str]) -> Worker:
        """Pick (or start) the worker a tenant's next cell belongs in."""
        with self._lock:
            if self._closed:
                raise errors.SandboxError("fabric worker pool is closed")
            self._reap_dead_locked()
            candidates = [
                w
                for w in self._workers
                if w.is_alive()
                and w.cell_count() < self.cells_per_worker
                and (not self.tenant_isolation or w.tenant == tenant)
            ]
            if candidates:
                # Least-loaded, so cells spread rather than piling into the
                # first worker and making one kill unusually expensive.
                return min(candidates, key=lambda w: w.cell_count())
            if len(self._workers) >= self.max_workers:
                raise errors.SandboxError(
                    f"fabric is at capacity: {len(self._workers)} workers x "
                    f"{self.cells_per_worker} cells. Raise max_workers or "
                    "cells_per_worker, or close some sandboxes."
                )
        return self._start_worker(tenant)

    def prewarm(self, tenant: Optional[str] = None, count: int = 1) -> int:
        """Start workers for *tenant* ahead of demand. Returns how many started.

        A worker costs ~160 ms to spawn: a fresh interpreter, the pyisolate
        import, and a cell pool. Paying that on a tenant's first request is the
        difference between a fabric that feels instant and one that does not,
        and it is entirely avoidable -- the supervisor knows its tenants before
        their traffic arrives.
        """
        started = 0
        for _ in range(count):
            with self._lock:
                if self._closed or len(self._workers) >= self.max_workers:
                    break
            try:
                self._start_worker(tenant)
            except errors.SandboxError:
                break
            started += 1
        return started

    def _start_worker(self, tenant: Optional[str]) -> Worker:
        worker = Worker(
            tenant=tenant,
            warm_per_spec=self._warm_per_spec,
            max_warm=self._max_warm,
            mem_bytes=self._worker_mem_bytes,
            env=self._env,
        )
        with self._lock:
            if self._closed:
                worker.stop()
                raise errors.SandboxError("fabric worker pool is closed")
            self._workers.append(worker)
            self._stats.workers_started += 1
        return worker

    def _reap_dead_locked(self) -> None:
        alive = []
        for worker in self._workers:
            if worker.is_alive():
                alive.append(worker)
            else:
                if worker.dead_reason is None:
                    # Nobody killed it; it crashed, was OOM-killed, or exited.
                    self._stats.workers_died += 1
                    worker.dead_reason = (
                        f"worker exited unexpectedly (rc={worker.returncode})"
                    )
        self._workers = alive

    # --- the kill domain ---

    def recycle(self, worker: Worker, reason: str) -> None:
        """Kill *worker* and drop it. Everything it hosted goes with it.

        This is what the whole three-level design exists for: a cell that will
        not stop is reclaimed by killing the process it lives in. The cost is
        the other cells in that worker, which is why ``tenant_isolation``
        defaults to on -- so that cost lands on one tenant.
        """
        logger.warning(
            "recycling fabric worker %s (pid=%s, tenant=%r): %s",
            worker.id,
            worker.pid,
            worker.tenant,
            reason,
        )
        worker.kill(reason)
        with self._lock:
            if worker in self._workers:
                self._workers.remove(worker)
            self._stats.workers_killed += 1

    # --- cells ---

    def open_cell(
        self,
        *,
        tenant: Optional[str] = None,
        allowed_imports: Optional[list[str]] = None,
        preimport: Optional[list[str]] = None,
    ) -> tuple[Worker, str]:
        worker = self.placement_for(tenant)
        cell_id = f"c{next(self._cell_ids)}"
        try:
            worker.open_cell(
                cell_id, allowed_imports=allowed_imports, preimport=preimport
            )
        except WorkerDied:
            # The worker died between placement and the open. Retire it and let
            # the caller land on a fresh one rather than surfacing a race.
            self.recycle(worker, "worker died during cell open")
            worker = self.placement_for(tenant)
            worker.open_cell(
                cell_id, allowed_imports=allowed_imports, preimport=preimport
            )
        with self._lock:
            self._stats.cells_opened += 1
        return worker, cell_id

    def run(
        self,
        worker: Worker,
        cell_id: str,
        frame: dict[str, Any],
        *,
        timeout: Optional[float],
    ) -> None:
        """Run one operation, recycling the worker if the guest never returns."""
        try:
            worker.run(cell_id, frame, timeout=timeout)
        except TimeoutError as exc:
            self.recycle(
                worker, f"cell {cell_id} exceeded its deadline; killing the worker"
            )
            raise errors.WallTimeExceeded(
                f"cell {cell_id} exceeded {timeout}s and did not return. A "
                "running sub-interpreter cannot be reclaimed, so the worker "
                "process hosting it was killed; cells sharing that worker were "
                "lost with it."
            ) from exc

    def close_cell(self, worker: Worker, cell_id: str) -> None:
        try:
            worker.close_cell(cell_id)
        finally:
            with self._lock:
                self._stats.cells_closed += 1

    # --- observability ---

    def stats(self) -> dict[str, Any]:
        with self._lock:
            self._reap_dead_locked()
            workers = list(self._workers)
            counters = self._stats.as_dict()
        counters["workers_live"] = len(workers)
        counters["cells_live"] = sum(w.cell_count() for w in workers)
        counters["tenant_isolation"] = self.tenant_isolation
        return counters

    def worker_report(self) -> list[dict[str, Any]]:
        """Per-worker placement view, for dashboards and admission checks."""
        with self._lock:
            workers = list(self._workers)
        return [
            {
                "id": w.id,
                "pid": w.pid,
                "tenant": w.tenant,
                "cells": w.cell_count(),
                "alive": w.is_alive(),
                "uptime_s": round(time.monotonic() - w.started_at, 3),
            }
            for w in workers
        ]

    # --- teardown ---

    def close(self) -> None:
        with self._lock:
            self._closed = True
            workers = list(self._workers)
            self._workers.clear()
        for worker in workers:
            worker.stop()

    def __enter__(self) -> "WorkerPool":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FabricSandbox:
    """Sandbox handle over a cell hosted in a worker process."""

    def __init__(
        self,
        name: str,
        *,
        pool: WorkerPool,
        allowed_imports: Optional[list[str]] = None,
        preimport: Optional[list[str]] = None,
        tenant: Optional[str] = None,
        wall_time_ms: Optional[int] = None,
    ) -> None:
        subinterpreter.require_available_for_fabric()
        self.name = name
        self._pool = pool
        self._tenant = tenant
        self._allowed_imports = list(allowed_imports or [])
        self.wall_time_ms = wall_time_ms
        self._lock = threading.Lock()
        self._posted: list[Any] = []
        self._logs: list[Any] = []
        self._metrics: list[Any] = []
        self._requests: list[Any] = []
        self._backend = "fabric"
        self._closed = False
        # Handle-surface attributes the Sandbox wrapper reads directly.
        self._cgroup_path: Optional[str] = None
        self._quarantine_reason: Optional[str] = None
        self.termination_reason: Optional[str] = None
        self.quota_enforcement = "worker_kill"
        self._worker, self._cell_id = pool.open_cell(
            tenant=tenant, allowed_imports=self._allowed_imports, preimport=preimport
        )

    # --- the cell ABI ---

    def exec(self, src: str) -> None:
        self._run({"op": "exec", "source": src})

    def call(
        self,
        func: str,
        *args: Any,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Any:
        if not isinstance(func, str) or not func:
            raise TypeError("func must be a dotted name")
        if "." not in func:
            raise ValueError(f"expected a dotted name, got {func!r}")
        self._run(
            {
                "op": "call",
                "target": func,
                "args": list(args),
                "kwargs": kwargs,
            },
            timeout=timeout,
        )
        with self._lock:
            if not self._posted:
                raise errors.SandboxError(f"call to {func!r} returned no result")
            return self._posted.pop()

    def recv(self, timeout: Optional[float] = None) -> Any:
        deadline = time.monotonic() + (timeout or 0.0)
        while True:
            self._collect()
            with self._lock:
                if self._posted:
                    return self._posted.pop(0)
            if timeout is None or time.monotonic() >= deadline:
                raise errors.TimeoutError(f"no message from sandbox '{self.name}'")
            time.sleep(0.002)

    # --- supervisor surface ---

    def is_alive(self) -> bool:
        return not self._closed and self._worker.is_alive()

    def kill(self, timeout: float = 0.2) -> bool:
        """Kill the worker hosting this cell. Unlike a cell, this always works."""
        del timeout
        if self._closed:
            return True
        self._pool.recycle(self._worker, f"sandbox {self.name} killed")
        self._closed = True
        return True

    def cancel(self, timeout: float = 0.2) -> bool:
        return self.kill(timeout)

    def stop(self, timeout: float = 0.2) -> None:
        self.close(timeout)

    def close(self, timeout: float = 0.2) -> None:
        del timeout
        if self._closed:
            return
        self._closed = True
        self._collect()
        self._pool.close_cell(self._worker, self._cell_id)

    def reap(self) -> bool:
        self.close()
        return True

    def quarantine(self, reason: str = "manual quarantine") -> None:
        self._quarantine_reason = reason
        self.kill()

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self._backend,
            "tenant": self._tenant,
            "worker": self._worker.id,
            "worker_pid": self._worker.pid,
            "cell": self._cell_id,
            "posted": len(self._posted),
            "requests": len(self._requests),
            "fabric": self._pool.stats(),
        }

    def profile(self) -> dict[str, Any]:
        return self.stats()

    def snapshot(self) -> dict[str, Any]:
        """Configuration, not guest state: an interpreter cannot be captured."""
        return {
            "name": self.name,
            "backend": self._backend,
            "tenant": self._tenant,
            "allowed_imports": sorted(self._allowed_imports),
            "wall_time_ms": self.wall_time_ms,
        }

    def get_broker_requests(self) -> list[Any]:
        self._collect()
        with self._lock:
            return list(self._requests)

    def reset_config(self) -> dict[str, Any]:
        raise NotImplementedError(
            "a sub-interpreter cannot be reset to a pristine state, so a cell "
            "is never reused across tenants. Close this sandbox and spawn "
            "another; the worker keeps a warm cell so that costs ~1ms."
        )

    def reset(self, *args: Any, **kwargs: Any) -> None:
        self.reset_config()

    def enable_tracing(self) -> None:
        raise NotImplementedError(
            "syscall tracing is a process-backend feature; a fabric worker runs "
            "many tenants' cells and has no per-cell syscall boundary to trace"
        )

    def get_syscall_log(self) -> list[str]:
        return []

    def get_denial_events(self) -> list[dict[str, str]]:
        return []

    def __enter__(self) -> "FabricSandbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- internals ---

    def _run(self, frame: dict[str, Any], timeout: Optional[float] = None) -> None:
        if self._closed:
            raise errors.SandboxError(f"sandbox '{self.name}' is closed")
        limit = timeout
        if limit is None and self.wall_time_ms is not None:
            limit = self.wall_time_ms / 1000.0
        try:
            self._pool.run(self._worker, self._cell_id, frame, timeout=limit)
        except (errors.WallTimeExceeded, WorkerDied):
            self._closed = True
            self._collect()
            raise
        finally:
            self._collect()

    def _collect(self) -> None:
        try:
            messages = self._worker.drain(self._cell_id)
        except Exception:  # pragma: no cover - worker gone mid-drain
            return
        for kind, payload in messages:
            with self._lock:
                if kind == "post":
                    self._posted.append(payload)
                elif kind == "log":
                    self._logs.append(payload)
                elif kind == "metric":
                    self._metrics.append(payload)
                elif kind == "request":
                    self._requests.append(payload)


#: Process-wide fabric, created lazily so importing pyisolate on a build without
#: sub-interpreters costs nothing.
_default_pool: Optional[WorkerPool] = None
_default_pool_lock = threading.Lock()


def default_pool() -> WorkerPool:
    global _default_pool
    with _default_pool_lock:
        if _default_pool is None:
            subinterpreter.require_available_for_fabric()
            _default_pool = WorkerPool()
        return _default_pool


def reset_default_pool() -> None:
    """Drop the process-wide fabric. Used by tests and supervisor shutdown."""
    global _default_pool
    with _default_pool_lock:
        pool, _default_pool = _default_pool, None
    if pool is not None:
        pool.close()


__all__ = [
    "FabricSandbox",
    "FabricStats",
    "Worker",
    "WorkerDied",
    "WorkerPool",
    "default_pool",
    "reset_default_pool",
]
