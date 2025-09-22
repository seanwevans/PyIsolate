import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os
import types

bpf_manager = types.ModuleType("pyisolate.bpf.manager")


class DummyBPFManager:
    def load(self, *a, **k):
        pass

    def hot_reload(self, *a, **k):
        pass

    def open_ring_buffer(self):
        return iter(())


sys.modules["pyisolate.bpf.manager"] = bpf_manager
bpf_manager.BPFManager = DummyBPFManager

import pytest

import pyisolate as iso
import pyisolate.policy as policy


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
