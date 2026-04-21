import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

import pyisolate as iso
from pyisolate.bpf.manager import BPFManager
from pyisolate.capabilities import (
    ROOT,
    ClockCapability,
    FilesystemCapability,
    NetworkCapability,
    RandomCapability,
    RootCapability,
    SecretCapability,
    SubprocessCapability,
)


def test_root_cap_type() -> None:
    assert isinstance(ROOT, RootCapability)


def test_reload_with_cap(monkeypatch, tmp_path) -> None:
    called = {}

    def fake_hot_reload(self, path):
        called["path"] = path

    monkeypatch.setattr(BPFManager, "hot_reload", fake_hot_reload)
    p = tmp_path / "p.json"
    p.write_text("{}")
    iso.reload_policy(str(p), ROOT)
    assert called["path"] == str(p)


def test_shutdown_with_cap() -> None:
    sup = iso.Supervisor()
    sb = sup.spawn("cap")
    sup.shutdown(ROOT)
    assert not sb._thread.is_alive()


def test_filesystem_capability_allows_only_handed_paths(tmp_path) -> None:
    allowed = tmp_path / "allowed"
    denied = tmp_path / "denied"
    allowed.mkdir()
    denied.mkdir()
    (allowed / "ok.txt").write_text("ok")
    (denied / "no.txt").write_text("no")

    sup = iso.Supervisor()
    sb = sup.spawn(
        "fs-cap",
        capabilities={"filesystem": FilesystemCapability.from_paths(str(allowed))},
    )
    try:
        sb.exec(f"post(open({str(allowed / 'ok.txt')!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec(f"post(open({str(denied / 'no.txt')!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sup.shutdown(ROOT)


def test_secret_capability_is_explicitly_handed() -> None:
    sup = iso.Supervisor()
    sb = sup.spawn(
        "secret-cap",
        capabilities={"secrets": SecretCapability.from_mapping({"api_key": "abc123"})},
    )
    try:
        sb.exec("post(caps['secrets'].get('api_key').decode())")
        assert sb.recv(timeout=1) == "abc123"
    finally:
        sup.shutdown(ROOT)


def test_subprocess_capability_brokered() -> None:
    sup = iso.Supervisor()
    sb = sup.spawn("subproc-block")
    try:
        sb.exec("import subprocess; subprocess.run(['echo', 'hi'])")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    sb = sup.spawn(
        "subproc-allow",
        capabilities={"subprocess": SubprocessCapability.from_commands("echo")},
    )
    try:
        sb.exec(
            "import subprocess; out = subprocess.run(['echo', 'hi']); post(out.stdout.strip())"
        )
        assert sb.recv(timeout=1) == "hi"
    finally:
        sup.shutdown(ROOT)


def test_network_and_entropy_capabilities() -> None:
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    sup = iso.Supervisor()
    sb = sup.spawn("net-cap-block")
    try:
        sb.exec(f"import socket; s=socket.socket(); s.connect(({host!r}, {port}))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    sb = sup.spawn(
        "net-cap-allow",
        capabilities={
            "network": NetworkCapability.from_destinations(f"{host}:{port}"),
            "random": RandomCapability(),
            "clock": ClockCapability(),
        },
    )
    try:
        sb.exec(
            f"import socket, os, time; s=socket.socket(); s.connect(({host!r}, {port})); post((len(os.urandom(8)), time.time() > 0))"
        )
        size, has_time = sb.recv(timeout=1)
        assert size == 8
        assert has_time is True
    finally:
        sup.shutdown(ROOT)
        srv.close()
