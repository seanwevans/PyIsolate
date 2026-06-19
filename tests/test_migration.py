import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import importlib

import pytest

import pyisolate as iso

migration_mod = importlib.import_module("pyisolate.migration")


def test_migrate_rejects_non_local_host_without_local_restore(monkeypatch):
    calls = []

    def fail_checkpoint(*args, **kwargs):
        calls.append("checkpoint")
        raise AssertionError("checkpoint should not be called for remote hosts")

    def fail_restore(*args, **kwargs):
        calls.append("restore")
        raise AssertionError("restore should not be called for remote hosts")

    monkeypatch.setattr(migration_mod, "checkpoint", fail_checkpoint)
    monkeypatch.setattr(migration_mod, "restore", fail_restore)

    with pytest.raises(NotImplementedError, match="remote sandbox migration"):
        iso.migrate(object(), "migration.example.com", b"k" * 32)

    assert calls == []


@pytest.mark.parametrize("host", ["", "localhost", "127.0.0.1", "::1"])
def test_migrate_allows_only_local_checkpoint_restore(monkeypatch, host):
    sandbox = object()
    key = b"k" * 32
    restored = object()
    calls = []

    def fake_checkpoint(received_sandbox, received_key):
        calls.append(("checkpoint", received_sandbox, received_key))
        return b"checkpoint-blob"

    def fake_restore(received_blob, received_key):
        calls.append(("restore", received_blob, received_key))
        return restored

    monkeypatch.setattr(migration_mod, "checkpoint", fake_checkpoint)
    monkeypatch.setattr(migration_mod, "restore", fake_restore)

    assert iso.migrate(sandbox, host, key) is restored
    assert calls == [
        ("checkpoint", sandbox, key),
        ("restore", b"checkpoint-blob", key),
    ]
