import signal

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


def test_sigxcpu_handler_scoped_to_sandbox_thread():
    orig = signal.getsignal(signal.SIGXCPU)
    assert orig is not thread._sigxcpu_handler

    sb = thread.SandboxThread("handler")
    sb._inbox.put("import signal; post(signal.getsignal(signal.SIGXCPU))")
    sb._inbox.put(thread._STOP)
    sb.run()
    assert sb.recv(timeout=1) is thread._sigxcpu_handler
    assert signal.getsignal(signal.SIGXCPU) is orig


def test_output_quota_is_hard_ceiling():
    sb = thread.SandboxThread("output", max_output_bytes=8)
    sb.start()
    try:
        sb.exec("post('this is bigger than 8')")
        with pytest.raises(errors.OutputExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "OutputExceeded"
    finally:
        sb.stop()


def test_wall_time_quota_is_hard_ceiling():
    sb = thread.SandboxThread("wall", wall_ms=5)
    sb.start()
    try:
        sb.exec("while True:\n    pass")
        with pytest.raises(errors.WallTimeExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "WallTimeExceeded"
    finally:
        sb.stop()


def test_open_files_quota_is_hard_ceiling(tmp_path):
    path = tmp_path / "data.txt"
    path.write_text("x")
    sb = thread.SandboxThread("fds", max_open_files=1)
    sb.start()
    try:
        sb.exec(
            f"f1 = open({str(path)!r}); f2 = open({str(path)!r}); post('never reached')"
        )
        with pytest.raises(errors.OpenFilesExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "OpenFilesExceeded"
    finally:
        sb.stop()
