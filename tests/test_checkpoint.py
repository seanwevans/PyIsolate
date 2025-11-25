import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json
import os
import types

bpf_manager = types.ModuleType("pyisolate.bpf.manager")


class DummyBPFManager:
    def __init__(self):
        self.loaded = False
        self.policy_maps = {}

    def load(self, *a, **k):
        self.loaded = True

    def hot_reload(self, *a, **k):
        import json

        path = k.get("policy_path") or (a[0] if a else None)
        if path is None:
            raise RuntimeError("Policy file not found: <unknown>")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Policy file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON in policy file {path}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Policy data must be a JSON object")
        self.policy_maps = data

    def _run(self, *a, **k):
        return True

    def open_ring_buffer(self):
        return iter(())


sys.modules["pyisolate.bpf.manager"] = bpf_manager
bpf_manager.BPFManager = DummyBPFManager

import pytest

import pyisolate as iso
import pyisolate.policy as policy


def _make_blob(payload, key):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    nonce = b"\x00" * 12
    data = json.dumps(payload).encode("utf-8")
    aead = ChaCha20Poly1305(key)
    return nonce + aead.encrypt(nonce, data, b"")


def test_checkpoint_roundtrip():
    key = os.urandom(32)
    sb = iso.spawn("cp")
    try:
        sb.exec("post(5)")
        assert sb.recv(timeout=0.5) == 5
        snap = sb.snapshot()
        blob = iso.checkpoint(sb, key)
        sb2 = iso.restore(blob, key)
        try:
            assert sb2.snapshot() == snap
            sb2.exec("post(6)")
            assert sb2.recv(timeout=0.5) == 6
        finally:
            sb2.close()
    finally:
        pass


def test_checkpoint_requires_32_byte_key():
    sb = iso.spawn("cp")
    try:
        with pytest.raises(ValueError, match="32 bytes"):
            iso.checkpoint(sb, b"short")
    finally:
        sb.close()


def test_restore_requires_32_byte_key():
    key = os.urandom(32)
    sb = iso.spawn("cp")
    blob = iso.checkpoint(sb, key)
    with pytest.raises(ValueError, match="32 bytes"):
        iso.restore(blob, b"1" * 16)


def test_checkpoint_rejects_unserializable():
    key = os.urandom(32)
    sb = iso.spawn("cp", policy=policy.Policy())
    try:
        with pytest.raises(ValueError, match="JSON serializable"):
            iso.checkpoint(sb, key)
    finally:
        sb.close()


def test_checkpoint_restores_imports_and_numa():
    key = os.urandom(32)
    allowed_imports = ["statistics", "math"]
    numa_node = 0
    sb = iso.spawn("custom", allowed_imports=allowed_imports, numa_node=numa_node)
    try:
        snap = sb.snapshot()
        assert snap["allowed_imports"] == sorted(set(allowed_imports))
        assert snap["numa_node"] == numa_node
        blob = iso.checkpoint(sb, key)
        sb2 = iso.restore(blob, key)
        try:
            restored = sb2.snapshot()
            assert restored["allowed_imports"] == sorted(set(allowed_imports))
            assert restored["numa_node"] == numa_node
            sb2.exec(
                "import math, statistics\npost(math.sqrt(16) + statistics.mean([0, 2]))"
            )
            assert pytest.approx(sb2.recv(timeout=0.5)) == 5.0
        finally:
            sb2.close()
    finally:
        pass


@pytest.mark.parametrize(
    "payload, message",
    [
        ([], "expected JSON object"),
        ({}, "non-empty string"),
        ({"name": ""}, "non-empty string"),
        ({"name": 123}, "non-empty string"),
    ],
)
def test_restore_rejects_malformed_payload(payload, message):
    key = os.urandom(32)
    blob = _make_blob(payload, key)
    with pytest.raises(ValueError, match=message):
        iso.restore(blob, key)


def test_checkpoint_closes_on_serialization_failure():
    key = os.urandom(32)

    class SpySandbox:
        def __init__(self):
            self.closed = False

        def snapshot(self):
            return {"bad": object()}

        def close(self):
            self.closed = True

    sandbox = SpySandbox()
    with pytest.raises(ValueError, match="JSON serializable"):
        iso.checkpoint(sandbox, key)
    assert sandbox.closed
