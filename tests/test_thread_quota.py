import signal
import threading

import pytest

from pyisolate import errors
from pyisolate.runtime import thread


def test_cpu_quota_is_debug_telemetry_without_watchdog(monkeypatch):
    def fake_thread_time():
        fake_thread_time.current += 0.002
        return fake_thread_time.current

    fake_thread_time.current = 0.0
    monkeypatch.setattr(thread.time, "thread_time", fake_thread_time)

    sb = thread.SandboxThread("cpu", cpu_ms=1)
    sb.start()
    try:
        sb.exec("post('ok')")
        assert sb.recv(timeout=1) == "ok"
        assert sb.stats.cpu_ms > sb.cpu_quota_ms
        assert sb.termination_reason is None
    finally:
        sb.stop()


def test_memory_quota_is_debug_telemetry_without_watchdog():
    sb = thread.SandboxThread("mem", mem_bytes=1024)
    sb.start()
    try:
        sb.exec("x = ' ' * (2 * 1024 * 1024)\npost('ok')")
        assert sb.recv(timeout=1) == "ok"
        assert sb.stats.mem_bytes > sb.mem_quota_bytes
        assert sb.termination_reason is None
    finally:
        sb.stop()


def test_sigxcpu_handler_scoped_to_sandbox_thread():
    orig = signal.getsignal(signal.SIGXCPU)
    assert orig is not thread._sigxcpu_handler

    sb = thread.SandboxThread("handler", allowed_imports=["signal"])
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


def test_open_files_quota_releases_on_explicit_close(tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")

    policy = type("Policy", (), {"fs": {str(tmp_path)}})()
    sb = thread.SandboxThread("files-close", policy=policy, open_files_max=1)
    sb.start()
    try:
        sb.exec(
            f"path = {str(target)!r}\n"
            "for _ in range(10):\n"
            "    fh = open(path, 'r')\n"
            "    assert fh.read() == 'ok'\n"
            "    fh.close()\n"
            "post('ok')"
        )
        assert sb.recv(timeout=1) == "ok"
    finally:
        sb.stop()


def test_open_files_quota_close_is_idempotent(tmp_path):
    target = tmp_path / "data.txt"
    target.write_text("ok", encoding="utf-8")

    policy = type("Policy", (), {"fs": {str(tmp_path)}})()
    sb = thread.SandboxThread("files-close-idempotent", policy=policy, open_files_max=1)
    sb.start()
    try:
        sb.exec(
            f"path = {str(target)!r}\n"
            "fh = open(path, 'r')\n"
            "fh.close()\n"
            "fh.close()\n"
            "fh = open(path, 'r')\n"
            "fh.close()\n"
            "post('ok')"
        )
        assert sb.recv(timeout=1) == "ok"
        assert sb._open_files == 0
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
    sb = thread.SandboxThread("child", child_work_max=0, allowed_imports=["threading"])
    sb.start()
    try:
        sb.exec("import threading\nthreading.Thread(target=lambda: None).start()")
        with pytest.raises(errors.ChildWorkExceeded):
            sb.recv(timeout=1)
        assert sb.termination_reason == "child_work_exceeded"
    finally:
        sb.stop()


def test_reserve_release_child_work_contract():
    # The atomic reserve/release pair enforces the quota and floors at zero.
    sb = thread.SandboxThread("rr", child_work_max=2)
    sb._reserve_child_work()
    sb._reserve_child_work()
    assert sb._child_work == 2
    with pytest.raises(errors.ChildWorkExceeded):
        sb._reserve_child_work()
    sb._release_child_work()
    assert sb._child_work == 1
    sb._reserve_child_work()  # a freed slot can be reused
    assert sb._child_work == 2
    for _ in range(5):  # release never drives the counter negative
        sb._release_child_work()
    assert sb._child_work == 0


def test_child_work_counter_is_mutated_only_under_its_lock():
    # The counter is incremented on the sandbox thread (start) and decremented on
    # each child thread (completion); those read-modify-writes must be serialized
    # by _child_work_lock or they race and lose updates. Rather than chase the
    # rare lost update (the inline += is "mostly" atomic under the GIL, so a
    # natural-race test is unreliable), assert the invariant directly: every
    # mutation of _child_work must happen while _child_work_lock is held. Driving
    # real child-thread starts through the inline, unlocked accounting trips this.
    sb = thread.SandboxThread("locked", child_work_max=None)
    sandboxed_cls = thread._make_sandbox_thread_class(sb)
    lock = sb._child_work_lock
    backing = {"value": sb._child_work}
    violations: list[str] = []

    class _Probe(type(sb)):
        @property
        def _child_work(self):
            return backing["value"]

        @_child_work.setter
        def _child_work(self, value):
            # A non-reentrant lock that acquires here means no one (including the
            # current thread) holds it -- i.e. this mutation is happening outside
            # the lock, which is the bug.
            if lock.acquire(blocking=False):
                lock.release()
                violations.append(f"unlocked write -> {value}")
            backing["value"] = value

    sb.__class__ = _Probe

    starters = 4
    per_starter = 25
    ready = threading.Barrier(starters)
    errors_seen: list[BaseException] = []

    def starter() -> None:
        try:
            ready.wait()
            children = [sandboxed_cls(target=lambda: None) for _ in range(per_starter)]
            for child in children:
                child.start()
            for child in children:
                child.join()
        except BaseException as exc:  # pragma: no cover - surfaced via list
            errors_seen.append(exc)

    workers = [threading.Thread(target=starter) for _ in range(starters)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    assert not errors_seen
    assert violations == []
    assert backing["value"] == 0
