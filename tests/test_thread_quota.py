import pytest

from pyisolate import errors
from pyisolate.runtime import thread


def test_cpu_quota_enforced_without_watchdog(monkeypatch):
    def fake_thread_time():
        fake_thread_time.current += 0.002
        return fake_thread_time.current

    fake_thread_time.current = 0.0
    monkeypatch.setattr(thread.time, "thread_time", fake_thread_time)

    sb = thread.SandboxThread("cpu", cpu_ms=1)
    sb.start()
    try:
        sb.exec("pass")
        with pytest.raises(errors.CPUExceeded):
            sb.recv(timeout=1)
    finally:
        sb.stop()


def test_memory_quota_enforced_without_watchdog():
    sb = thread.SandboxThread("mem", mem_bytes=1024)
    sb.start()
    try:
        sb.exec("x = ' ' * (2 * 1024 * 1024)")
        with pytest.raises(errors.MemoryExceeded):
            sb.recv(timeout=1)
    finally:
        sb.stop()
