import builtins
import socket
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import errors, policy
from pyisolate.runtime.protocol import AttachCgroupRequest
from pyisolate.runtime.thread import SandboxThread, _sigxcpu_handler


def test_sigxcpu_handler_raises():
    with pytest.raises(errors.CPUExceeded):
        _sigxcpu_handler(None, None)


def test_globals_restored_after_sandbox_close():
    iso.shutdown()

    orig_open = builtins.open
    orig_connect = socket.socket.connect

    sb = iso.spawn("restore", policy=policy.Policy())
    try:
        sb.exec("post('ok')")
        assert sb.recv(timeout=1) == "ok"
    finally:
        sb.close()

    assert builtins.open is orig_open
    assert socket.socket.connect is orig_connect


def test_other_thread_unaffected_by_sandbox():
    iso.shutdown()

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    results = {}

    def worker():
        client = socket.socket()
        client.connect(("127.0.0.1", port))
        client.close()
        with open(__file__, "r") as f:
            results["line"] = f.readline()

    sb = iso.spawn("restore", policy=policy.Policy())
    try:
        sb.exec("import time; time.sleep(0.2); post('done')")
        t = threading.Thread(target=worker)
        t.start()
        conn, _ = server.accept()
        conn.close()
        server.close()
        t.join()
        assert results["line"]
        assert sb.recv(timeout=1) == "done"
    finally:
        sb.close()



def test_attach_cgroup_control_message_is_idempotent(monkeypatch):
    from pyisolate import cgroup

    calls = {"attach": 0, "delete": 0}

    def fake_attach(path):
        calls["attach"] += 1

    def fake_delete(path):
        calls["delete"] += 1

    monkeypatch.setattr(cgroup, "attach_current", fake_attach)
    monkeypatch.setattr(cgroup, "delete", fake_delete)

    t = SandboxThread(name="msg-idem")
    t.start()
    try:
        t._inbox.put(AttachCgroupRequest(old_path=None, msg_id=7))
        t._inbox.put(AttachCgroupRequest(old_path=None, msg_id=7))
        t.exec("post('ok')")
        assert t.recv(timeout=0.5) == "ok"
    finally:
        t.stop()

    # One call comes from thread startup attach, one from unique control message.
    assert calls["attach"] == 2
    assert calls["delete"] == 0


def test_sandbox_threading_patch_is_local_and_does_not_touch_global_start():
    iso.shutdown()

    original_start = threading.Thread.start
    started_outside = {"count": 0}
    failures = []

    def outside_worker() -> None:
        started_outside["count"] += 1

    sb = SandboxThread(name="local-threading", child_work_max=1)
    sb.start()
    try:
        sb.exec(
            """
import threading

def worker():
    pass

t = threading.Thread(target=worker)
t.start()
t.join()
post('sandbox-ok')
"""
        )
        assert sb.recv(timeout=1) == "sandbox-ok"

        # A host thread should still use the original global start implementation.
        host_thread = threading.Thread(target=outside_worker)
        host_thread.start()
        host_thread.join(timeout=1)
        assert started_outside["count"] == 1
        assert threading.Thread.start is original_start

        # While sandbox work is running, repeatedly start host threads and
        # ensure no global behavior bleed happens.
        sb.exec(
            """
import threading
import time

def worker():
    time.sleep(0.03)

t = threading.Thread(target=worker)
t.start()
t.join()
post('sandbox-loop')
"""
        )

        for _ in range(10):
            t = threading.Thread(target=outside_worker)
            t.start()
            t.join(timeout=1)
            if threading.Thread.start is not original_start:
                failures.append("threading.Thread.start changed globally")

        assert sb.recv(timeout=1) == "sandbox-loop"
        assert not failures
        assert threading.Thread.start is original_start
    finally:
        sb.stop()
