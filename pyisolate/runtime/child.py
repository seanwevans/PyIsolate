"""Guest runtime for the ``backend="process"`` isolation mode.

This module is the entry point executed in a *fresh* interpreter for every
process-backed sandbox (``python -m pyisolate.runtime.child <fd>``).  Because it
runs in its own OS process, guest code cannot reach the supervisor's address
space at all -- the in-process object-graph escapes that defeat the
sub-interpreter backend (walking ``().__class__.__base__.__subclasses__()`` to
recover an unrestricted ``__import__``) can still run here, but they only ever
touch *this* process, which later hardening layers (seccomp, rlimits, Landlock,
cgroups) confine at the kernel level.

The parent speaks a tiny length-framed JSON protocol over an inherited
``AF_UNIX`` socket.  JSON is deliberate: the parent must never ``pickle.loads``
bytes produced by untrusted guest code, so values crossing the boundary are
restricted to JSON-serializable data.

Parent -> child frames::

    {"op": "bootstrap", "name": ..., "allowed_imports": [...] | null,
     "fs": [...] | null, "tcp": [...] | null}
    {"op": "exec", "source": "..."}
    {"op": "call", "target": "mod.fn", "args": [...], "kwargs": {...}}
    {"op": "stop"}

Child -> parent frames::

    {"ev": "ready"}
    {"ev": "post", "message": <json>}
    {"ev": "log", "level": ..., "message": ..., "fields": {...}}
    {"ev": "metric", "name": ..., "value": ..., "tags": {...}}
    {"ev": "done"}
    {"ev": "error", "exc_type": "PolicyError", "message": "..."}
"""

from __future__ import annotations

import json
import socket
import struct
import sys
from pathlib import Path
from typing import Any

from .. import errors
from .confine import apply_confinement
from .thread import _SAFE_BUILTINS, _blocked_open, _make_importer, _thread_local

_LEN = struct.Struct("!I")


def _send_frame(sock: socket.socket, obj: dict[str, Any]) -> None:
    # json.dumps raises TypeError for non-serializable payloads; that propagates
    # into guest code (e.g. out of ``post``) instead of silently crossing the
    # boundary, which is the contract for the process backend.
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(_LEN.pack(len(data)) + data)


def _recv_exact(sock: socket.socket, size: int) -> bytes | None:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> dict[str, Any] | None:
    header = _recv_exact(sock, _LEN.size)
    if header is None:
        return None
    (size,) = _LEN.unpack(header)
    body = _recv_exact(sock, size)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


class _GuestChannel:
    """Guest-side implementations of the ``post``/``log``/``metric``/``request``
    cell operations that frame back to the supervisor process."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def post(self, message: Any) -> None:
        _send_frame(self._sock, {"ev": "post", "message": message})

    def log(self, level: str, message: str, **fields: Any) -> None:
        _send_frame(
            self._sock,
            {"ev": "log", "level": level, "message": message, "fields": fields},
        )

    def metric(self, name: str, value: Any, tags: dict[str, str] | None = None) -> None:
        _send_frame(
            self._sock,
            {"ev": "metric", "name": name, "value": value, "tags": tags or {}},
        )

    def request(self, capability: str, action: str, payload: Any = None) -> None:
        # Broker mediation for the process backend is not yet wired; deny by
        # default rather than silently succeeding.
        raise errors.PolicyError(
            f"broker request {capability!r}/{action!r} is not available "
            "for the process backend"
        )


def _install_guest_context(
    *,
    allowed_imports: list[str] | None,
    fs: list[str] | None,
    tcp: list[str] | None,
) -> None:
    """Populate the thread-local state the reused import/FS/network guards read.

    ``_thread_local.sandbox`` is ``None`` here (there is no ``SandboxThread`` in
    the child); the guards in :mod:`pyisolate.runtime.thread` already treat that
    as "no in-process quota counters" and still enforce the policy allow-lists.
    """

    _thread_local.sandbox = None
    _thread_local.authority = None
    _thread_local.runtime_policy = None
    _thread_local.fs_capability = None
    _thread_local.net_capability = None
    _thread_local.subprocess_capability = None
    _thread_local.clock_capability = None
    _thread_local.random_capability = None
    _thread_local.fs = (
        [Path(p).resolve(strict=False) for p in fs] if fs is not None else None
    )
    if tcp is not None:
        _thread_local.tcp = set(tcp)
    elif hasattr(_thread_local, "tcp"):
        del _thread_local.tcp


def _build_guest_globals(
    channel: _GuestChannel, allowed_imports: list[str] | None
) -> dict[str, Any]:
    builtins_dict = _SAFE_BUILTINS.copy()
    builtins_dict["open"] = _blocked_open
    builtins_dict["__import__"] = _make_importer(allowed_imports or [])
    return {
        "post": channel.post,
        "log": channel.log,
        "metric": channel.metric,
        "request": channel.request,
        "__builtins__": builtins_dict,
    }


def _run_exec(source: str, guest_globals: dict[str, Any]) -> None:
    exec(source, guest_globals, guest_globals)  # noqa: S102 - sandboxed guest code


def _run_call(
    target: str, args: list[Any], kwargs: dict[str, Any], guest_globals: dict[str, Any]
) -> Any:
    importer = guest_globals["__builtins__"]["__import__"]
    try:
        module_name, func_name = target.rsplit(".", 1)
    except ValueError as exc:
        raise errors.SandboxError(
            f"call target {target!r} must include a module path (e.g. 'module.func')"
        ) from exc
    mod = importer(module_name, fromlist=["_"])
    func = object.__getattribute__(mod, func_name)
    return func(*args, **(kwargs or {}))


def _serve(sock: socket.socket) -> None:
    bootstrap = _recv_frame(sock)
    if bootstrap is None or bootstrap.get("op") != "bootstrap":
        return
    allowed_imports = bootstrap.get("allowed_imports")
    _install_guest_context(
        allowed_imports=allowed_imports,
        fs=bootstrap.get("fs"),
        tcp=bootstrap.get("tcp"),
    )
    channel = _GuestChannel(sock)
    guest_globals = _build_guest_globals(channel, allowed_imports)

    # Confine the process *before* any guest code runs. Everything this module
    # needs is already imported; guest imports (openat/mmap/read) are unaffected
    # by the deny-list, but execve/ptrace/module-load/etc. now kill the process.
    if bootstrap.get("confine", True):
        report = apply_confinement(
            mem_bytes=bootstrap.get("mem_bytes"),
            cpu_seconds=bootstrap.get("cpu_seconds"),
            require_seccomp=bool(bootstrap.get("require_seccomp", False)),
        )
        _send_frame(
            sock,
            {
                "ev": "confinement",
                "seccomp": report.seccomp,
                "seccomp_denied": report.seccomp_denied,
                "rlimits": report.rlimits,
                "skipped": report.skipped,
            },
        )

    _send_frame(sock, {"ev": "ready"})

    while True:
        frame = _recv_frame(sock)
        if frame is None:
            return
        op = frame.get("op")
        if op == "stop":
            return
        try:
            if op == "exec":
                _run_exec(frame.get("source", ""), guest_globals)
            elif op == "call":
                result = _run_call(
                    frame.get("target", ""),
                    frame.get("args", []),
                    frame.get("kwargs", {}),
                    guest_globals,
                )
                channel.post(result)
            else:
                raise errors.SandboxError(f"unknown cell operation: {op!r}")
        except BaseException as exc:  # noqa: BLE001 - surface every failure to host
            _send_frame(
                sock,
                {
                    "ev": "error",
                    "exc_type": type(exc).__name__,
                    "message": str(exc),
                },
            )
        else:
            _send_frame(sock, {"ev": "done"})


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
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
