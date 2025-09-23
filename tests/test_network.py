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


@pytest.mark.parametrize(
    "family, host, suffix",
    [
        (socket.AF_INET, "127.0.0.1", ""),
        (socket.AF_INET6, "::1", ", 0, 0"),
    ],
)
def test_connect_guard_handles_multi_field_addresses(family, host, suffix):
    if family == socket.AF_INET6 and not socket.has_ipv6:
        pytest.skip("IPv6 is not available")

    srv = socket.socket(family)
    try:
        srv.bind((host, 0))
    except OSError as exc:
        srv.close()
        pytest.skip(f"cannot bind to {host}: {exc}")
    srv.listen(1)
    sockname = srv.getsockname()
    target_host, port = sockname[0], sockname[1]
    connect_args = f"({target_host!r}, {port}{suffix})"

    allowed_policy = policy.Policy().allow_tcp(f"{target_host}:{port}")
    sb_allow = iso.spawn("netguard-allow", policy=allowed_policy)
    try:
        code = (
            "import socket; "
            f"s=socket.socket({family}, socket.SOCK_STREAM); "
            f"s.connect({connect_args}); "
            "post('ok')"
        )
        sb_allow.exec(code)
        assert sb_allow.recv(timeout=1) == "ok"
    finally:
        sb_allow.close()

    sb_block = iso.spawn("netguard-block", policy=policy.Policy())
    try:
        code = (
            "import socket; "
            f"s=socket.socket({family}, socket.SOCK_STREAM); "
            f"s.connect({connect_args})"
        )
        sb_block.exec(code)
        with pytest.raises(iso.PolicyError):
            sb_block.recv(timeout=1)
    finally:
        sb_block.close()
        srv.close()
