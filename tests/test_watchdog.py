import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso


def teardown_module(module):
    iso.shutdown()


def test_cpu_quota_exceeded_via_watchdog():
    sb = iso.spawn("wdcpu", cpu_ms=10)
    try:
        sb.exec("while True: pass")
        with pytest.raises(iso.CPUExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_memory_quota_exceeded_via_watchdog():
    sb = iso.spawn("wdmem", mem_bytes=1024 * 1024)
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
