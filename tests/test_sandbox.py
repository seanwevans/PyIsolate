import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
import time
import logging
import gc
from pyisolate.bpf.manager import BPFManager


def test_spawn_returns_sandbox():
    sb = iso.spawn("t1")
    try:
        assert isinstance(sb, iso.Sandbox)
    finally:
        sb.close()


def test_exec_runs_code_and_recv():
    sb = iso.spawn("t2")
    try:
        sb.exec("post(42)")
        assert sb.recv(timeout=0.5) == 42
    finally:
        sb.close()


def test_call_returns_result():
    sb = iso.spawn("t3")
    try:
        result = sb.call("math.sqrt", 9)
        assert result == 3.0
    finally:
        sb.close()


def test_allowed_imports_success():
    sb = iso.spawn("imp_ok", allowed_imports=["math"])
    try:
        assert sb.call("math.sqrt", 16) == 4.0
    finally:
        sb.close()


def test_allowed_imports_blocked():
    sb = iso.spawn("imp_no", allowed_imports=["json"])
    try:
        with pytest.raises(iso.PolicyError):
            sb.call("math.sqrt", 4)
    finally:
        sb.close()


def test_recv_timeout_raises():
    sb = iso.spawn("t4")
    try:
        with pytest.raises(TimeoutError):
            sb.recv(timeout=0.1)
    finally:
        sb.close()


def test_call_raises_exception():
    sb = iso.spawn("t5")
    try:
        with pytest.raises(iso.SandboxError):
            sb.call("math.sqrt", -1)
    finally:
        sb.close()


def test_cpu_quota_exceeded(monkeypatch):
    def fake_rb(self):
        def gen():
            time.sleep(0.05)
            while True:
                time.sleep(0.01)
                yield {"name": "tcpu", "cpu_ms": 20, "rss_bytes": 0}

        return gen()

    monkeypatch.setattr(BPFManager, "open_ring_buffer", fake_rb)
    monkeypatch.setattr(BPFManager, "_run", lambda *a, **k: True)
    iso.shutdown()

    sb = iso.supervisor._supervisor.spawn("tcpu", cpu_ms=10)
    try:
        sb.exec("while True: pass")
        with pytest.raises(iso.CPUExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_memory_quota_exceeded(monkeypatch):
    def fake_rb(self):
        def gen():
            time.sleep(0.05)
            while True:
                time.sleep(0.01)
                yield {"name": "tmem", "cpu_ms": 0, "rss_bytes": 2 * 1024 * 1024}

        return gen()

    monkeypatch.setattr(BPFManager, "open_ring_buffer", fake_rb)
    monkeypatch.setattr(BPFManager, "_run", lambda *a, **k: True)
    iso.shutdown()

    sb = iso.supervisor._supervisor.spawn("tmem", mem_bytes=1024 * 1024)
    try:
        sb.exec("x = ' ' * (2 * 1024 * 1024)")
        with pytest.raises(iso.MemoryExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_policy_refresh_parses_yaml(tmp_path, monkeypatch):
    policy_file = tmp_path / "p.yml"
    policy_file.write_text("version: 0.1\n")

    import pyisolate.policy as policy

    monkeypatch.setattr(
        "pyisolate.bpf.manager.BPFManager.hot_reload", lambda *a, **k: None
    )

    iso.set_policy_token("tok")
    policy.refresh(str(policy_file), token="tok")


def test_context_manager_closes():
    with iso.spawn("ctx") as sb:
        sb.exec("post(1)")
        assert sb.recv(timeout=0.5) == 1

    assert not sb._thread.is_alive()


def test_dangerous_builtins_removed():
    sb = iso.spawn("builtins")
    try:
        sb.exec(
            "try:\n    eval('1')\nexcept NameError:\n    post('missing')\nelse:\n    post('present')"
        )
        assert sb.recv(timeout=0.5) == "missing"

        sb.exec(
            "try:\n    compile('1', '<s>', 'eval')\nexcept NameError:\n    post('missing')\nelse:\n    post('present')"
        )
        assert sb.recv(timeout=0.5) == "missing"

        sb.exec(
            "try:\n    getattr(1, 'bit_length')\nexcept NameError:\n    post('missing')\nelse:\n    post('present')"
        )
        assert sb.recv(timeout=0.5) == "missing"
    finally:
        sb.close()


def test_warning_on_gc_without_close(caplog):
    caplog.set_level(logging.WARNING)
    sb = iso.spawn("delwarn")
    thread = sb._thread
    del sb
    gc.collect()
    assert any("garbage-collected" in r.message for r in caplog.records)
    assert not thread.is_alive()
