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

    sb = iso.supervisor._get_supervisor().spawn("wdcpu", cpu_ms=10)
    try:
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

    sb = iso.supervisor._get_supervisor().spawn("wdmem", mem_bytes=1024 * 1024)
    try:
        sb.exec("x = ' ' * (2 * 1024 * 1024)")
        with pytest.raises(iso.MemoryExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_watchdog_thread_stops():
    sup = iso.supervisor._get_supervisor()
    iso.shutdown()
    assert not sup._watchdog.is_alive()


class _FakeBPF:
    def __init__(self, iterator_factory):
        self._iterator_factory = iterator_factory

    def open_ring_buffer(self):
        return self._iterator_factory()


class _FakeSupervisor:
    def __init__(self, iterator_factory):
        self._bpf = _FakeBPF(iterator_factory)

    def get_active_threads(self):
        return []


def test_watchdog_ignores_malformed_event_payloads(caplog):
    from pyisolate.watchdog import ResourceWatchdog

    def fake_iter():
        for event in ["bad-event", 123, None]:
            yield event
        while True:
            time.sleep(0.01)
            yield {"name": "noop", "cpu_ms": 0, "rss_bytes": 0}

    caplog.set_level("WARNING")
    wd = ResourceWatchdog(_FakeSupervisor(fake_iter), interval=0.01)
    wd.start()
    try:
        time.sleep(0.08)
        assert wd.is_alive()
    finally:
        wd.stop()

    assert "watchdog ignored non-mapping event payload" in caplog.text


def test_watchdog_survives_ring_buffer_iterator_exceptions(caplog):
    from pyisolate.watchdog import ResourceWatchdog

    class BoomIter:
        def __next__(self):
            raise RuntimeError("boom")

    caplog.set_level("ERROR")
    wd = ResourceWatchdog(_FakeSupervisor(BoomIter), interval=0.01)
    wd.start()
    try:
        time.sleep(0.08)
        assert wd.is_alive()
    finally:
        wd.stop()

    assert "watchdog ring-buffer iterator failed; resetting" in caplog.text
