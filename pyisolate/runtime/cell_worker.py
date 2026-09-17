"""Worker process that hosts sub-interpreter cells for the fabric.

This module is the entry point executed in a *fresh* interpreter for every
fabric worker (``python -m pyisolate.runtime.cell_worker <fd>``). A worker owns
a :class:`~pyisolate.runtime.subinterpreter.CellPool` and runs many cells inside
itself; the supervisor drives it over the same length-framed JSON protocol the
process backend uses.

Why a separate process at all, when a cell is already isolated from its
siblings: **a running sub-interpreter cannot be reclaimed.** ``close()`` refuses
while the guest is executing, there is no ``kill``, and an async exception aimed
at the thread does not reach the interpreter running in it. The only reclaim
that works is killing the process. So the worker is the kill domain: when a cell
overruns, the supervisor SIGKILLs the whole worker and starts a replacement,
which costs the other cells in that worker and nothing outside it. Sizing a
worker -- ideally one tenant per worker -- is therefore how a deployment chooses
its blast radius.

A worker is started with ``spawn`` semantics (a fresh ``sys.executable``), never
by forking the supervisor. Forking a process that already hosts sub-interpreters
and their threads segfaults, which is also why the backend's own runaway tests
shell out instead of calling ``os.fork``.

Parent -> worker frames::

    {"op": "hello", "warm_per_spec": N, "max_warm": N, "mem_bytes": N | null}
    {"op": "open", "cell": "<id>", "allowed_imports": [...], "preimport": [...]}
    {"op": "exec", "cell": "<id>", "seq": N, "source": "..."}
    {"op": "call", "cell": "<id>", "seq": N, "target": "mod.fn",
     "args": [...], "kwargs": {...}}
    {"op": "close", "cell": "<id>"}
    {"op": "stats"}
    {"op": "stop"}

Worker -> parent frames::

    {"ev": "ready", "pid": N, "python": "...", "free_threaded": bool}
    {"ev": "opened", "cell": "<id>", "interp": N}
    {"ev": "post" | "log" | "metric" | "request", "cell": "<id>", ...}
    {"ev": "done", "cell": "<id>", "seq": N}
    {"ev": "error", "cell": "<id>", "seq": N, "exc_type": "...", "message": "..."}
    {"ev": "closed", "cell": "<id>"}
    {"ev": "stats", "pool": {...}, "cells": N}
"""

from __future__ import annotations

import json
import resource
import socket
import struct
import sys
import threading
import traceback
from typing import Any, Optional

from .subinterpreter import Cell, CellPool, CellSpec, require_available

_LEN = struct.Struct("!I")

#: How often the pump forwards whatever cells have posted. A cell writes to its
#: own queue whenever guest code calls ``post``; without a pump those messages
#: would only reach the supervisor when the operation returns, so a guest that
#: posts and then blocks would look silent.
_PUMP_INTERVAL = 0.005


class _Channel:
    """Length-framed JSON over the inherited socket, safe for many senders.

    Cell operations run on their own threads so one slow guest cannot stall the
    worker's control loop, which means several threads frame concurrently. The
    lock keeps a frame from being interleaved with another on the wire.
    """

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._lock = threading.Lock()

    def send(self, obj: dict[str, Any]) -> None:
        try:
            data = json.dumps(obj).encode("utf-8")
        except TypeError:
            # A cell posted something JSON cannot carry. The cell bootstrap
            # already encodes guest payloads, so this is a bug on our side
            # rather than guest input; report it rather than killing the loop.
            data = json.dumps(
                {
                    "ev": "error",
                    "cell": obj.get("cell"),
                    "seq": obj.get("seq"),
                    "exc_type": "TypeError",
                    "message": "worker produced a non-serialisable frame",
                }
            ).encode("utf-8")
        with self._lock:
            try:
                self._sock.sendall(_LEN.pack(len(data)) + data)
            except OSError:
                # The supervisor is gone (it killed us, or it exited). Nothing
                # to report to, and raising here would only spam tracebacks out
                # of cell threads.
                pass

    def recv(self) -> Optional[dict[str, Any]]:
        header = self._recv_exact(_LEN.size)
        if header is None:
            return None
        (size,) = _LEN.unpack(header)
        body = self._recv_exact(size)
        if body is None:
            return None
        return json.loads(body.decode("utf-8"))

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


class _Worker:
    """Owns this process's cell pool and serves the supervisor's frames."""

    def __init__(self, channel: _Channel) -> None:
        self._channel = channel
        self._pool: Optional[CellPool] = None
        self._cells: dict[str, Cell] = {}
        self._lock = threading.Lock()
        self._stopping = threading.Event()
        self._pump: Optional[threading.Thread] = None

    # --- lifecycle ---

    def hello(self, frame: dict[str, Any]) -> None:
        mem_bytes = frame.get("mem_bytes")
        if mem_bytes:
            # The only memory cap available to a cell fabric.
            # ``sys.getallocatedblocks()`` is process-global rather than
            # per-interpreter on both free-threaded and GIL builds, so there is
            # no per-cell accounting to enforce; capping the worker's address
            # space is what makes a memory limit mean anything, and it is
            # another reason worker sizing is how blast radius gets chosen.
            try:
                resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            except (ValueError, OSError) as exc:  # pragma: no cover - host dependent
                self._channel.send(
                    {
                        "ev": "error",
                        "cell": None,
                        "seq": None,
                        "exc_type": type(exc).__name__,
                        "message": f"could not apply worker memory cap: {exc}",
                    }
                )
        self._pool = CellPool(
            warm_per_spec=int(frame.get("warm_per_spec", 1)),
            max_warm=int(frame.get("max_warm", 32)),
        )
        self._pump = threading.Thread(
            target=self._pump_loop, name="pyisolate-worker-pump", daemon=True
        )
        self._pump.start()
        self._channel.send(
            {
                "ev": "ready",
                "pid": _getpid(),
                "python": sys.version.split()[0],
                "free_threaded": not getattr(sys, "_is_gil_enabled", lambda: True)(),
            }
        )

    def open(self, frame: dict[str, Any]) -> None:
        cell_id = frame["cell"]
        assert self._pool is not None
        spec = CellSpec.build(
            frame.get("allowed_imports") or (),
            frame.get("preimport"),
        )
        cell = self._pool.acquire(spec)
        with self._lock:
            self._cells[cell_id] = cell
        self._channel.send({"ev": "opened", "cell": cell_id, "interp": cell.id})

    def close_cell(self, frame: dict[str, Any]) -> None:
        cell_id = frame["cell"]
        with self._lock:
            cell = self._cells.pop(cell_id, None)
        if cell is not None and self._pool is not None:
            self._forward(cell_id, cell)
            self._pool.release(cell)
        self._channel.send({"ev": "closed", "cell": cell_id})

    def stats(self) -> None:
        with self._lock:
            live = len(self._cells)
        pool = self._pool.stats() if self._pool is not None else {}
        self._channel.send({"ev": "stats", "pool": pool, "cells": live})

    # --- running guest work ---

    def dispatch(self, frame: dict[str, Any]) -> None:
        """Run one operation on a thread of its own.

        The worker must stay responsive while a guest runs: a cell that never
        returns would otherwise block ``stats`` and ``close`` for every other
        cell in this worker, and the supervisor would have no way to tell a
        wedged worker from a busy one.
        """
        cell_id = frame["cell"]
        with self._lock:
            cell = self._cells.get(cell_id)
        if cell is None:
            self._channel.send(
                {
                    "ev": "error",
                    "cell": cell_id,
                    "seq": frame.get("seq"),
                    "exc_type": "SandboxError",
                    "message": f"no open cell {cell_id!r}",
                }
            )
            return
        thread = threading.Thread(
            target=self._run_op,
            args=(cell_id, cell, frame),
            name=f"pyisolate-cell-{cell_id}",
            daemon=True,
        )
        thread.start()

    def _run_op(self, cell_id: str, cell: Cell, frame: dict[str, Any]) -> None:
        seq = frame.get("seq")
        try:
            if frame["op"] == "exec":
                cell.exec(frame.get("source", ""))
            else:
                self._run_call(cell, frame)
        except BaseException as exc:  # noqa: BLE001 - every failure goes to the host
            self._forward(cell_id, cell)
            self._channel.send(
                {
                    "ev": "error",
                    "cell": cell_id,
                    "seq": seq,
                    "exc_type": type(exc).__name__,
                    "message": _describe(exc),
                }
            )
            return
        self._forward(cell_id, cell)
        self._channel.send({"ev": "done", "cell": cell_id, "seq": seq})

    @staticmethod
    def _run_call(cell: Cell, frame: dict[str, Any]) -> None:
        """Resolve a dotted name inside the cell and post its result.

        Resolution happens in the cell so it goes through that interpreter's
        guarded ``__import__`` -- the allow-list applies to a ``call`` target
        exactly as it does to an ``import`` in guest source -- and so the worker
        never hands one of its own objects to the guest.
        """
        target = frame.get("target", "")
        module, _, attr = target.rpartition(".")
        if not module or not attr:
            raise ValueError(f"call target {target!r} must be a dotted name")
        payload = json.dumps(
            {"args": frame.get("args") or [], "kwargs": frame.get("kwargs") or {}}
        )
        cell.exec(
            f"_pyi_call = _pyi_json.loads({payload!r})\n"
            f"_pyi_mod = __import__({module!r}, fromlist=[{attr!r}])\n"
            f"post(getattr(_pyi_mod, {attr!r})"
            "(*_pyi_call['args'], **_pyi_call['kwargs']))\n"
        )

    # --- message forwarding ---

    def _forward(self, cell_id: str, cell: Cell) -> None:
        for kind, payload in cell.drain():
            self._channel.send({"ev": kind, "cell": cell_id, "payload": payload})

    def _pump_loop(self) -> None:
        while not self._stopping.wait(_PUMP_INTERVAL):
            with self._lock:
                items = list(self._cells.items())
            for cell_id, cell in items:
                try:
                    self._forward(cell_id, cell)
                except Exception:  # pragma: no cover - a retired cell mid-drain
                    continue

    # --- shutdown ---

    def shutdown(self) -> None:
        self._stopping.set()
        with self._lock:
            cells = list(self._cells.values())
            self._cells.clear()
        pool = self._pool
        if pool is None:
            return
        for cell in cells:
            # A cell still running cannot be retired; the pool records that
            # rather than blocking shutdown on a guest that never returns.
            pool.release(cell)
        pool.close()


def _describe(exc: BaseException) -> str:
    text = str(exc).strip()
    if text:
        return text.splitlines()[-1]
    return traceback.format_exception_only(type(exc), exc)[-1].strip()


def _getpid() -> int:
    import os

    return os.getpid()


def _serve(sock: socket.socket) -> None:
    channel = _Channel(sock)
    worker = _Worker(channel)
    try:
        require_available()
    except Exception as exc:  # pragma: no cover - guarded by the supervisor too
        channel.send(
            {
                "ev": "error",
                "cell": None,
                "seq": None,
                "exc_type": type(exc).__name__,
                "message": str(exc),
            }
        )
        return

    handlers = {
        "hello": worker.hello,
        "open": worker.open,
        "close": worker.close_cell,
    }
    try:
        while True:
            frame = channel.recv()
            if frame is None:
                return
            op = frame.get("op")
            if op == "stop":
                return
            try:
                if op in handlers:
                    handlers[op](frame)
                elif op == "stats":
                    worker.stats()
                elif op in ("exec", "call"):
                    worker.dispatch(frame)
                else:
                    raise ValueError(f"unknown worker operation: {op!r}")
            except BaseException as exc:  # noqa: BLE001 - never drop the loop
                channel.send(
                    {
                        "ev": "error",
                        "cell": frame.get("cell"),
                        "seq": frame.get("seq"),
                        "exc_type": type(exc).__name__,
                        "message": _describe(exc),
                    }
                )
    finally:
        worker.shutdown()


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 2
    fd = int(argv[1])
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, fileno=fd)
    try:
        _serve(sock)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    # A cell that never returned leaves its thread pinned inside a running
    # interpreter, and a normal exit would block on it forever. The supervisor
    # already has the result it is going to get, so leave immediately.
    import os

    os._exit(0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
