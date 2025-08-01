import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import time

import pytest

import pyisolate as iso
from pyisolate.bpf.manager import BPFManager


def teardown_module(module):
    iso.shutdown()


def test_cpu_quota_exceeded_via_watchdog(monkeypatch):
    def fake_rb(self):
        def gen():
            time.sleep(0.05)
            while True:
                time.sleep(0.01)
                yield {"name": "wdcpu", "cpu_ms": 20, "rss_bytes": 0}

        return gen()

    monkeypatch.setattr(BPFManager, "open_ring_buffer", fake_rb)
    monkeypatch.setattr(BPFManager, "_run", lambda *a, **k: True)
    iso.shutdown()

    sb = iso.supervisor._supervisor.spawn("wdcpu", cpu_ms=10)
    try:
        sb.exec("while True: pass")
        with pytest.raises(iso.CPUExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_memory_quota_exceeded_via_watchdog(monkeypatch):
    def fake_rb(self):
        def gen():
            time.sleep(0.05)
            while True:
                time.sleep(0.01)
                yield {"name": "wdmem", "cpu_ms": 0, "rss_bytes": 2 * 1024 * 1024}

        return gen()

    monkeypatch.setattr(BPFManager, "open_ring_buffer", fake_rb)
    monkeypatch.setattr(BPFManager, "_run", lambda *a, **k: True)
    iso.shutdown()

    sb = iso.supervisor._supervisor.spawn("wdmem", mem_bytes=1024 * 1024)
    try:
        sb.exec("x = ' ' * (2 * 1024 * 1024)")
        with pytest.raises(iso.MemoryExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_watchdog_thread_stops():
    sup = iso.supervisor._supervisor
    iso.shutdown()
    assert not sup._watchdog.is_alive()
