"""Sandbox migration utilities."""

from __future__ import annotations

import hmac
import json
import socket
import struct
from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from .checkpoint import checkpoint, restore
from .supervisor import Sandbox

_MAGIC = b"PYISOMIG1"
_HEADER_LIMIT = 16 * 1024
_DEFAULT_PORT = 8765


@dataclass(frozen=True)
class MigrationResponse:
    """Response returned by a remote migration endpoint."""

    ok: bool
    error: str | None = None


class MigrationProtocolError(ValueError):
    """Raised when a peer sends an invalid migration protocol message."""


def _parse_host(host: str) -> tuple[str, int]:
    if not host:
        raise ValueError("host must be a non-empty string")
    if "://" in host:
        raise ValueError("host must be in 'hostname[:port]' form")
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 host")
        address = host[1:end]
        remainder = host[end + 1 :]
        if not remainder:
            return address, _DEFAULT_PORT
        if not remainder.startswith(":"):
            raise ValueError("invalid host")
        port_text = remainder[1:]
    else:
        address, sep, port_text = host.rpartition(":")
        if not sep:
            return host, _DEFAULT_PORT
        if ":" in address:
            raise ValueError("IPv6 hosts with ports must use '[addr]:port' form")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("host port must be an integer") from exc
    if not 0 < port <= 65535:
        raise ValueError("host port must be between 1 and 65535")
    return address, port


def _mac(blob: bytes, key: bytes) -> str:
    return hmac.new(key, blob, sha256).hexdigest()


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = conn.recv(remaining)
        if not chunk:
            raise MigrationProtocolError("connection closed while reading message")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_json(conn: socket.socket, payload: dict[str, object]) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    conn.sendall(struct.pack("!I", len(data)) + data)


def _recv_json(conn: socket.socket) -> dict[str, object]:
    (size,) = struct.unpack("!I", _read_exact(conn, 4))
    if size > _HEADER_LIMIT:
        raise MigrationProtocolError("migration header is too large")
    try:
        payload = json.loads(_read_exact(conn, size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MigrationProtocolError("invalid migration JSON") from exc
    if not isinstance(payload, dict):
        raise MigrationProtocolError("invalid migration JSON")
    return payload


def send_checkpoint(
    host: str, blob: bytes, key: bytes, *, timeout: float | None = 10.0
) -> MigrationResponse:
    """Send encrypted checkpoint *blob* to the migration endpoint at *host*."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    address = _parse_host(host)
    header = {
        "magic": _MAGIC.decode("ascii"),
        "version": 1,
        "blob_len": len(blob),
        "auth": _mac(blob, key),
    }
    with socket.create_connection(address, timeout=timeout) as conn:
        _send_json(conn, header)
        conn.sendall(blob)
        response = _recv_json(conn)
    ok = response.get("ok")
    if not isinstance(ok, bool):
        raise MigrationProtocolError("invalid migration response")
    error = response.get("error")
    if error is not None and not isinstance(error, str):
        raise MigrationProtocolError("invalid migration response")
    return MigrationResponse(ok=ok, error=error)


def handle_migration_connection(
    conn: socket.socket,
    key: bytes,
    *,
    restore_fn: Callable[[bytes, bytes], Sandbox] = restore,
) -> MigrationResponse:
    """Restore one checkpoint received from *conn* and send a response."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    try:
        header = _recv_json(conn)
        if header.get("magic") != _MAGIC.decode("ascii") or header.get("version") != 1:
            raise MigrationProtocolError("unsupported migration protocol")
        blob_len = header.get("blob_len")
        auth = header.get("auth")
        if isinstance(blob_len, bool) or not isinstance(blob_len, int) or blob_len < 0:
            raise MigrationProtocolError("invalid checkpoint length")
        if not isinstance(auth, str):
            raise MigrationProtocolError("missing migration authenticator")
        blob = _read_exact(conn, blob_len)
        if not hmac.compare_digest(auth, _mac(blob, key)):
            raise MigrationProtocolError("invalid migration authenticator")
        restore_fn(blob, key)
        response = MigrationResponse(ok=True)
    except (
        Exception
    ) as exc:  # endpoint must convert all restore/protocol failures to a response
        response = MigrationResponse(ok=False, error=str(exc))
    _send_json(conn, {"ok": response.ok, "error": response.error})
    return response


def serve_migration_once(
    host: str, key: bytes, *, restore_fn: Callable[[bytes, bytes], Sandbox] = restore
) -> MigrationResponse:
    """Listen on *host* and handle a single migration request."""
    address = _parse_host(host)
    with socket.create_server(address) as server:
        conn, _peer = server.accept()
        with conn:
            return handle_migration_connection(conn, key, restore_fn=restore_fn)


def migrate(sandbox: Sandbox, host: str, key: bytes) -> MigrationResponse:
    """Migrate *sandbox* to *host* using an encrypted checkpoint."""
    blob = checkpoint(sandbox, key)
    return send_checkpoint(host, blob, key)


__all__ = [
    "MigrationProtocolError",
    "MigrationResponse",
    "handle_migration_connection",
    "migrate",
    "send_checkpoint",
    "serve_migration_once",
]
