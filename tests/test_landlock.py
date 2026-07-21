"""Tests for Landlock filesystem confinement of the process backend.

Landlock enforcement is unavailable on many kernels (including where this
suite typically runs), so the end-to-end enforcement test is gated on
``landlock_supported()`` plus an opt-in env flag, mirroring the live BPF
kernel-enforcement test. The mechanism-level logic that does not require the
kernel is tested unconditionally.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.runtime import landlock
from pyisolate.runtime.child import _net_connect_ports
from pyisolate.runtime.process_backend import (
    _extract_fs_read_write,
    _extract_fs_tcp,
)

requires_landlock = pytest.mark.skipif(
    not landlock.landlock_supported(),
    reason="kernel does not support Landlock",
)

requires_landlock_net = pytest.mark.skipif(
    not landlock.net_supported(),
    reason="kernel does not support Landlock network rules (ABI < 4)",
)

live_landlock_net = pytest.mark.skipif(
    not (
        landlock.net_supported()
        and os.environ.get("PYISOLATE_LIVE_LANDLOCK_TESTS") == "1"
    ),
    reason="live Landlock network test requires ABI >= 4 and "
    "PYISOLATE_LIVE_LANDLOCK_TESTS=1",
)

live_landlock = pytest.mark.skipif(
    not (
        landlock.landlock_supported()
        and os.environ.get("PYISOLATE_LIVE_LANDLOCK_TESTS") == "1"
    ),
    reason="live Landlock enforcement test requires Landlock and "
    "PYISOLATE_LIVE_LANDLOCK_TESTS=1",
)


def test_handled_access_fs_is_masked_by_abi():
    # Newer access rights must only be requested on ABIs that support them,
    # otherwise landlock_create_ruleset rejects the ruleset.
    abi1 = landlock.handled_access_fs(1)
    abi2 = landlock.handled_access_fs(2)
    abi3 = landlock.handled_access_fs(3)
    abi5 = landlock.handled_access_fs(5)
    assert not abi1 & landlock.ACCESS_FS["REFER"]
    assert abi2 & landlock.ACCESS_FS["REFER"]
    assert not abi2 & landlock.ACCESS_FS["TRUNCATE"]
    assert abi3 & landlock.ACCESS_FS["TRUNCATE"]
    assert not abi3 & landlock.ACCESS_FS["IOCTL_DEV"]
    assert abi5 & landlock.ACCESS_FS["IOCTL_DEV"]
    # Read/write/execute are available from ABI 1.
    for name in ("READ_FILE", "WRITE_FILE", "EXECUTE", "READ_DIR"):
        assert abi1 & landlock.ACCESS_FS[name]


def test_path_beneath_attr_is_packed_to_twelve_bytes():
    # struct landlock_path_beneath_attr is packed (8-byte access + 4-byte fd);
    # any padding would misalign the fd and make the kernel reject the rule.
    import ctypes

    assert ctypes.sizeof(landlock._PathBeneathAttr) == 12


def test_abi_and_support_are_consistent():
    assert landlock.landlock_supported() == (landlock.abi_version() >= 1)


def test_extract_fs_read_write_from_legacy_policy_dedupes():
    policy = iso.policy.Policy().allow_fs("/data").allow_read("/etc/hostname")
    read, write = _extract_fs_read_write(policy)
    # allow_fs grants read+write, so /data is writable only; the explicit
    # read path stays read-only and nothing is duplicated across the sets.
    assert write == ["/data"]
    assert read == ["/etc/hostname"]


def test_extract_fs_tcp_handles_legacy_policy_methods():
    # Regression: Policy.allow_fs/allow_tcp are methods, not rule collections;
    # the extractor must read the .fs/.tcp attributes instead of iterating them.
    policy = iso.policy.Policy().allow_fs("/data").allow_tcp("127.0.0.1:80")
    fs, tcp = _extract_fs_tcp(policy)
    assert fs == ["/data"]
    assert tcp == ["127.0.0.1:80"]


def test_apply_landlock_is_a_noop_when_unsupported():
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; skip the unsupported-path check")
    report = landlock.apply_landlock(["/tmp"], None)
    assert report.applied is False
    assert report.skipped == "unsupported"


def test_apply_landlock_requires_support_when_required():
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; skip the required-failure check")
    with pytest.raises(RuntimeError):
        landlock.apply_landlock(["/tmp"], None, require=True)


@requires_landlock
def test_process_sandbox_reports_landlock_applied(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = iso.policy.Policy().allow_fs(str(allowed))
    with iso.spawn("ll-applied", policy=policy, backend="process") as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert report is not None
        assert report["landlock"] is True
        assert report["landlock_rules"] >= 1


# Recover the real ``open`` from a stdlib module's globals, bypassing the
# process backend's blocked-open guard, so the test exercises Landlock (the
# kernel layer) rather than the Python guard.
_REAL_READ = """
def _real_open(path):
    for cls in ().__class__.__base__.__subclasses__():
        if cls.__name__ == "catch_warnings":
            return cls()._module.__builtins__["open"](path)
    raise RuntimeError("no real open")
post(_real_open({path!r}).read())
"""


def test_handled_access_net_is_masked_by_abi():
    # TCP network rules only exist from ABI 4; requesting them earlier makes
    # landlock_create_ruleset reject the ruleset.
    assert landlock.handled_access_net(3) == 0
    assert landlock.handled_access_net(4) == landlock.ACCESS_NET["CONNECT_TCP"]
    assert landlock.handled_access_net(6) & landlock.ACCESS_NET["CONNECT_TCP"]
    # Only egress (connect) is confined by this layer; bind is out of scope.
    assert not landlock.handled_access_net(4) & landlock.ACCESS_NET["BIND_TCP"]


def test_net_port_attr_and_ruleset_attr_net_layout():
    import ctypes

    # struct landlock_net_port_attr is two u64s (allowed_access, port).
    assert ctypes.sizeof(landlock._NetPortAttr) == 16
    # struct landlock_ruleset_attr with handled_access_net is two u64s; passing
    # this larger struct is only valid on an ABI >= 4 kernel.
    assert ctypes.sizeof(landlock._RulesetAttrNet) == 16


def test_net_supported_matches_abi():
    assert landlock.net_supported() == (landlock.abi_version() >= 4)


def test_connect_ports_from_destinations_parses_and_dedupes():
    ports, exact = landlock.connect_ports_from_destinations(
        ["1.2.3.4:443", "example.com:80", "10.0.0.1:443"]
    )
    # 443 appears twice but is de-duplicated; order is preserved.
    assert ports == [443, 80]
    assert exact is True


def test_connect_ports_from_destinations_flags_unparseable():
    # A bare hostname has no port to allow-list, so the result is inexact and
    # the caller must not build a default-deny network ruleset from it.
    ports, exact = landlock.connect_ports_from_destinations(
        ["example.com", "1.2.3.4:443"]
    )
    assert ports == [443]
    assert exact is False


def test_connect_ports_from_destinations_rejects_out_of_range():
    ports, exact = landlock.connect_ports_from_destinations(["h:0", "h:70000"])
    assert ports == []
    assert exact is False


def test_net_connect_ports_helper_gates_on_exactness():
    # No allow-list -> no network Landlock at all.
    assert _net_connect_ports(None) is None
    assert _net_connect_ports([]) is None
    # A fully-parseable allow-list yields the port set.
    assert _net_connect_ports(["1.2.3.4:443", "h:80"]) == [443, 80]
    # Any unrepresentable entry degrades to the userspace guard (None), rather
    # than a kernel rule that would block the permitted-but-portless entry.
    assert _net_connect_ports(["example.com", "1.2.3.4:443"]) is None


def test_apply_landlock_net_required_but_unsupported_raises():
    if landlock.net_supported():
        pytest.skip("kernel supports Landlock net; skip the required-failure check")
    with pytest.raises(RuntimeError):
        landlock.apply_landlock(None, None, connect_ports=[443], require=True)


@requires_landlock_net
def test_process_sandbox_reports_landlock_net_applied():
    policy = iso.policy.Policy().allow_tcp("127.0.0.1:9")
    with iso.spawn("ll-net-applied", policy=policy, backend="process") as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert report is not None
        assert report["landlock_net"] is True
        assert report["landlock_net_ports"] >= 1


# Recover a real socket and attempt a TCP connect, bypassing the userspace
# network guard, so the test exercises Landlock (the kernel layer) rather than
# the Python guard.
_REAL_CONNECT = """
import socket
def _connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
    finally:
        s.close()
_connect({host!r}, {port!r})
post("connected")
"""


@live_landlock_net
def test_landlock_blocks_disallowed_ports_but_allows_permitted():
    import socket as _socket
    import threading

    server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    allowed_port = server.getsockname()[1]

    def _accept_loop():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            conn.close()

    threading.Thread(target=_accept_loop, daemon=True).start()

    policy = iso.policy.Policy().allow_tcp(f"127.0.0.1:{allowed_port}")
    with iso.spawn(
        "ll-net-enforce", policy=policy, backend="process", allowed_imports=["socket"]
    ) as sb:
        # Connecting to the allow-listed port is permitted by Landlock.
        sb.exec(_REAL_CONNECT.format(host="127.0.0.1", port=allowed_port))
        assert sb.recv(timeout=5) == "connected"
        # A port the policy never named is denied at the kernel level.
        sb.exec(_REAL_CONNECT.format(host="127.0.0.1", port=allowed_port + 1))
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)
    server.close()


@live_landlock
def test_landlock_blocks_disallowed_reads_but_allows_permitted(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("ok", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")

    policy = iso.policy.Policy().allow_fs(str(allowed))
    with iso.spawn("ll-enforce", policy=policy, backend="process") as sb:
        # Reading an allowed file via the real open is permitted by Landlock.
        sb.exec(_REAL_READ.format(path=str(allowed / "ok.txt")))
        assert sb.recv(timeout=5) == "ok"
        # Reading outside the allow-list is denied at the kernel level.
        sb.exec(_REAL_READ.format(path=str(secret)))
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)
