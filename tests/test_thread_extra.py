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
from pyisolate.runtime.thread import _sigxcpu_handler


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
