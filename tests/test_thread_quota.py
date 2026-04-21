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


def test_wall_time_quota_hard_stop():
    sb = thread.SandboxThread("wall", wall_time_ms=5)
    sb.start()
    try:
        sb.exec("while True:\n    pass")
        with pytest.raises(errors.WallTimeExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "wall_time_exceeded"
    finally:
        sb.stop()


def test_open_files_quota_hard_stop(tmp_path):
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("a", encoding="utf-8")
    second.write_text("b", encoding="utf-8")

    policy = type("Policy", (), {"fs": {str(tmp_path)}})()
    sb = thread.SandboxThread("files", policy=policy, open_files_max=1)
    sb.start()
    try:
        sb.exec(
            f"f1 = open({str(first)!r}, 'r')\n"
            f"f2 = open({str(second)!r}, 'r')\n"
            "post('ok')"
        )
        with pytest.raises(errors.OpenFilesExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "open_files_exceeded"
    finally:
        sb.stop()


def test_output_quota_hard_stop():
    sb = thread.SandboxThread("output", output_bytes_max=4)
    sb.start()
    try:
        sb.exec("post('12345')")
        with pytest.raises(errors.OutputExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "output_exceeded"
    finally:
        sb.stop()


def test_network_ops_quota_hard_stop():
    policy = type("Policy", (), {"tcp": {"127.0.0.1:80"}})()
    sb = thread.SandboxThread("net", policy=policy, network_ops_max=0)
    sb.start()
    try:
        sb.exec("import socket\nsocket.socket().connect(('127.0.0.1', 80))")
        with pytest.raises(errors.NetworkExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "network_exceeded"
    finally:
        sb.stop()


def test_child_work_quota_hard_stop():
    sb = thread.SandboxThread("child", child_work_max=0)
    sb.start()
    try:
        sb.exec("import threading\nthreading.Thread(target=lambda: None).start()")
        with pytest.raises(errors.ChildWorkExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "child_work_exceeded"
    finally:
        sb.stop()
