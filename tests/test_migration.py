import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate import migration

KEY = b"k" * 32


class FakeClientSocket:
    def __init__(self, response: bytes):
        self.response = bytearray(response)
        self.sent = bytearray()

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        if not self.response:
            return b""
        chunk = self.response[:size]
        del self.response[:size]
        return bytes(chunk)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None


def _encoded_response(ok: bool, error: str | None = None) -> bytes:
    left, right = socket.socketpair()
    try:
        migration._send_json(left, {"ok": ok, "error": error})
        return right.recv(4096)
    finally:
        left.close()
        right.close()


def test_migrate_uses_host_and_does_not_restore_locally(monkeypatch):
    sandbox = object()
    blob = b"encrypted-checkpoint"
    fake = FakeClientSocket(_encoded_response(True))
    calls = {}

    def fake_checkpoint(seen_sandbox, seen_key):
        calls["checkpoint"] = (seen_sandbox, seen_key)
        return blob

    def fake_create_connection(address, timeout=None):
        calls["address"] = address
        calls["timeout"] = timeout
        return fake

    def fail_restore(*args, **kwargs):  # pragma: no cover - should never run
        raise AssertionError("migrate must not restore locally for remote hosts")

    monkeypatch.setattr(migration, "checkpoint", fake_checkpoint)
    monkeypatch.setattr(migration, "restore", fail_restore)
    monkeypatch.setattr(migration.socket, "create_connection", fake_create_connection)

    response = migration.migrate(sandbox, "migration.example:9443", KEY)

    assert response == migration.MigrationResponse(ok=True, error=None)
    assert calls["checkpoint"] == (sandbox, KEY)
    assert calls["address"] == ("migration.example", 9443)
    assert calls["timeout"] == 10.0
    assert blob in fake.sent


def test_endpoint_restores_authenticated_checkpoint():
    server, client = socket.socketpair()
    restored = []
    result = []
    blob = b"sealed"

    def restore_fn(seen_blob, seen_key):
        restored.append((seen_blob, seen_key))
        return object()

    def run_server():
        with server:
            result.append(
                migration.handle_migration_connection(
                    server, KEY, restore_fn=restore_fn
                )
            )

    thread = threading.Thread(target=run_server)
    thread.start()
    try:
        migration._send_json(
            client,
            {
                "magic": "PYISOMIG1",
                "version": 1,
                "blob_len": len(blob),
                "auth": migration._mac(blob, KEY),
            },
        )
        client.sendall(blob)
        response = migration._recv_json(client)
    finally:
        client.close()
        thread.join(timeout=1)

    assert response == {"ok": True, "error": None}
    assert result == [migration.MigrationResponse(ok=True, error=None)]
    assert restored == [(blob, KEY)]


def test_endpoint_rejects_unauthenticated_checkpoint():
    server, client = socket.socketpair()
    restored = []
    blob = b"sealed"

    def restore_fn(seen_blob, seen_key):  # pragma: no cover - should never run
        restored.append((seen_blob, seen_key))
        return object()

    thread = threading.Thread(
        target=lambda: migration.handle_migration_connection(
            server, KEY, restore_fn=restore_fn
        )
    )
    thread.start()
    try:
        migration._send_json(
            client,
            {
                "magic": "PYISOMIG1",
                "version": 1,
                "blob_len": len(blob),
                "auth": "0" * 64,
            },
        )
        client.sendall(blob)
        response = migration._recv_json(client)
    finally:
        client.close()
        server.close()
        thread.join(timeout=1)

    assert response["ok"] is False
    assert "authenticator" in response["error"]
    assert restored == []


def test_endpoint_rejects_oversized_checkpoint_before_reading_it():
    # blob_len is peer-controlled and read into memory before the HMAC can be
    # checked, so the endpoint must reject an oversized declaration up front
    # instead of buffering whatever the peer streams.
    server, client = socket.socketpair()
    restored = []
    result = []

    def restore_fn(seen_blob, seen_key):  # pragma: no cover - should never run
        restored.append((seen_blob, seen_key))
        return object()

    def run_server():
        with server:
            result.append(
                migration.handle_migration_connection(
                    server, KEY, restore_fn=restore_fn, max_blob_len=1024
                )
            )

    thread = threading.Thread(target=run_server)
    thread.start()
    try:
        migration._send_json(
            client,
            {
                "magic": "PYISOMIG1",
                "version": 1,
                "blob_len": 1025,
                "auth": "0" * 64,
            },
        )
        response = migration._recv_json(client)
    finally:
        client.close()
        thread.join(timeout=1)

    assert response["ok"] is False
    assert "maximum size" in response["error"]
    assert result == [
        migration.MigrationResponse(ok=False, error="checkpoint exceeds maximum size")
    ]
    assert restored == []
