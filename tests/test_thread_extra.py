import builtins
import socket
import sys
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


from pyisolate.runtime.thread import _orig_connect


def test_globals_restored_after_sandbox_close():
    iso.shutdown()
    import io

    builtins.open = io.open
    socket.socket.connect = _orig_connect
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
