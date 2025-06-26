import socket
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy


def test_connect_blocked():
    sb = iso.spawn("netblock", policy=policy.Policy())
    try:
        sb.exec("import socket; s=socket.socket(); s.connect(('127.0.0.1', 9999))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_connect_allowed():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    sb = iso.spawn("netallow", policy=policy.Policy().allow_tcp(f"{host}:{port}"))
    try:
        code = f"import socket; s=socket.socket(); s.connect(('127.0.0.1', {port})); post('ok')"
        sb.exec(code)
        assert sb.recv(timeout=1) == "ok"
    finally:
        sb.close()
        srv.close()
