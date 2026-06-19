import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import importlib
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


bpf_manager.BPFManager = DummyBPFManager

# Install the stub while this module imports the rest of the package, but keep a
# reference to the real module so it can be restored.  The supervisor imports
# ``pyisolate.bpf.manager`` lazily, so leaving the stub in ``sys.modules`` would
# leak the dummy manager into every test collected/run afterward (their
# singleton supervisor would silently use ``DummyBPFManager``).  The stub is
# re-installed per test via the autouse fixture below instead.
_ORIG_BPF_MANAGER = sys.modules.get("pyisolate.bpf.manager")
sys.modules["pyisolate.bpf.manager"] = bpf_manager

import pytest

import pyisolate as iso
import pyisolate.policy as policy
import pyisolate.supervisor as _supervisor_mod
from pyisolate.capabilities import FilesystemCapability

checkpoint_mod = importlib.import_module("pyisolate.checkpoint")

# Restore the real module after this module's imports so collection of other
# test modules is unaffected.
if _ORIG_BPF_MANAGER is not None:
    sys.modules["pyisolate.bpf.manager"] = _ORIG_BPF_MANAGER
else:
    sys.modules.pop("pyisolate.bpf.manager", None)


@pytest.fixture(autouse=True)
def _use_dummy_bpf_manager():
    """Activate the in-memory BPF manager stub only while a checkpoint test runs.

    The supervisor singleton is reset so it is recreated against the stub, and
    both the module entry and the singleton are restored on teardown to keep the
    rest of the suite on the real BPF manager.
    """
    orig_module = sys.modules.get("pyisolate.bpf.manager")
    sys.modules["pyisolate.bpf.manager"] = bpf_manager
    _supervisor_mod._supervisor = None
    try:
        yield
    finally:
        _supervisor_mod._supervisor = None
        if orig_module is not None:
            sys.modules["pyisolate.bpf.manager"] = orig_module
        else:
            sys.modules.pop("pyisolate.bpf.manager", None)


def _make_blob(payload, key):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    nonce = b"\x00" * 12
    data = json.dumps(payload).encode("utf-8")
    aead = ChaCha20Poly1305(key)
    sealed = nonce + aead.encrypt(nonce, data, b"")
    return b"PYISOCP1" + len(sealed).to_bytes(4, "big") + sealed


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


def test_checkpoint_restores_capabilities(tmp_path):
    key = os.urandom(32)
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    target = allowed / "ok.txt"
    target.write_text("ok", encoding="utf-8")

    sb = iso.spawn(
        "cap-cp",
        capabilities={"filesystem": FilesystemCapability.from_paths(str(allowed))},
    )
    try:
        blob = iso.checkpoint(sb, key)
        sb2 = iso.restore(blob, key)
        try:
            sb2.exec(f"post(open({str(target)!r}).read())")
            assert sb2.recv(timeout=0.5) == "ok"
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


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("cpu_ms", 0, "cpu_ms.*positive integer"),
        ("cpu_ms", -1, "cpu_ms.*positive integer"),
        ("cpu_ms", True, "cpu_ms.*positive integer"),
        ("cpu_ms", "10", "cpu_ms.*positive integer"),
        ("mem_bytes", 0, "mem_bytes.*positive integer"),
        ("mem_bytes", 1.5, "mem_bytes.*positive integer"),
        ("numa_node", -1, "numa_node.*non-negative integer"),
        ("numa_node", False, "numa_node.*non-negative integer"),
        ("numa_node", "0", "numa_node.*non-negative integer"),
    ],
)
def test_restore_rejects_malformed_resource_fields_after_decrypt(
    monkeypatch, field, value, message
):
    key = os.urandom(32)
    payload = {"name": "bad-resource", field: value}
    blob = _make_blob(payload, key)

    def fail_spawn(*args, **kwargs):
        raise AssertionError("spawn should not be called for invalid payloads")

    monkeypatch.setattr(checkpoint_mod, "spawn", fail_spawn)
    with pytest.raises(ValueError, match=f"invalid checkpoint payload: .*{message}"):
        iso.restore(blob, key)


@pytest.mark.parametrize(
    "value",
    [
        "math",
        ["math", ""],
        ["math", 1],
        ["math", None],
        {"0": "math"},
    ],
)
def test_restore_rejects_malformed_allowed_imports_after_decrypt(monkeypatch, value):
    key = os.urandom(32)
    blob = _make_blob({"name": "bad-imports", "allowed_imports": value}, key)

    def fail_spawn(*args, **kwargs):
        raise AssertionError("spawn should not be called for invalid payloads")

    monkeypatch.setattr(checkpoint_mod, "spawn", fail_spawn)
    with pytest.raises(
        ValueError,
        match="invalid checkpoint payload: 'allowed_imports'.*list of non-empty strings",
    ):
        iso.restore(blob, key)


@pytest.mark.parametrize(
    "value",
    [
        [],
        ["filesystem"],
        {"": {}},
        {"filesystem": {}},
        {"filesystem": {"__pyisolate_capability__": "read_path"}},
        {
            "filesystem": {
                "__pyisolate_capability__": "secrets",
                "values": {"api": "zz"},
            }
        },
    ],
)
def test_restore_rejects_malformed_capabilities_after_decrypt(monkeypatch, value):
    key = os.urandom(32)
    blob = _make_blob({"name": "bad-caps", "capabilities": value}, key)

    def fail_spawn(*args, **kwargs):
        raise AssertionError("spawn should not be called for invalid payloads")

    monkeypatch.setattr(checkpoint_mod, "spawn", fail_spawn)
    with pytest.raises(
        ValueError,
        match="invalid checkpoint payload: 'capabilities'.*serialized capability mapping",
    ):
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


def test_restore_rejects_truncated_envelope_before_decrypt(monkeypatch):
    key = os.urandom(32)

    from cryptography.hazmat.primitives.ciphers import aead as aead_mod

    def fail_decrypt(self, nonce, data, aad):
        raise AssertionError("decrypt should not be called")

    monkeypatch.setattr(aead_mod.ChaCha20Poly1305, "decrypt", fail_decrypt)
    with pytest.raises(ValueError, match="envelope length"):
        iso.restore(b"PYISOCP1" + (99).to_bytes(4, "big") + b"x", key)


def test_restore_rejects_bad_envelope_magic():
    key = os.urandom(32)
    with pytest.raises(ValueError, match="envelope"):
        iso.restore(b"NOTMAGIC" + (0).to_bytes(4, "big"), key)
