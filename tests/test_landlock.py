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
from pyisolate.runtime import confine, landlock
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


# -- filesystem default-deny ------------------------------------------------
#
# A sandbox whose policy names no filesystem paths used to get no filesystem
# confinement at all: confine._apply_landlock returned early, so the guest kept
# full read access to the host (/root, $HOME, /var) and could write anywhere.
# That contradicted the deny-by-default posture the import allow-list already
# takes, and it also meant hardened rollout mode could not fail closed, because
# require_landlock was never consulted on that path.


def test_default_deny_handles_the_fs_class_without_policy_paths():
    # The decision that matters: with no policy paths and default_deny_fs on,
    # the filesystem access class is still handled, so Landlock denies
    # everything outside the interpreter's own runtime paths.
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; would confine the test process")
    report = landlock.apply_landlock(None, None, default_deny_fs=True)
    # Unsupported kernel, so nothing is applied -- but the attempt was made and
    # recorded, rather than skipped as "no_rules" before reaching the kernel.
    assert report.skipped == "unsupported"


def test_opting_out_of_default_deny_skips_the_fs_class():
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; would confine the test process")
    report = landlock.apply_landlock(None, None, default_deny_fs=False)
    assert report.skipped == "unsupported"


def test_no_rules_is_only_reachable_with_default_deny_off(monkeypatch):
    # Force the "kernel supports Landlock" branch without touching the real
    # kernel, to prove which combination reaches the no-op path.
    monkeypatch.setattr(landlock, "abi_version", lambda: 1)
    report = landlock.apply_landlock(None, None, default_deny_fs=False)
    assert report.skipped == "no_rules"
    assert report.applied is False


def test_hardened_mode_fails_closed_without_policy_paths():
    # The regression this guards: require_landlock=True with no policy paths
    # used to return silently, leaving a "hardened" guest with unrestricted
    # filesystem access on a kernel that cannot enforce Landlock.
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; would confine the test process")
    report = confine.ConfinementReport()
    with pytest.raises((RuntimeError, OSError)):
        confine._apply_landlock(
            report,
            fs_read=None,
            fs_write=None,
            net_connect_ports=None,
            require_landlock=True,
        )


def test_missing_landlock_is_recorded_even_without_policy_paths():
    # Best-effort mode must still say the layer is absent. Previously the report
    # was silent, so a no-policy sandbox looked confined when it was not.
    if landlock.landlock_supported():
        pytest.skip("kernel supports Landlock; would confine the test process")
    report = confine.ConfinementReport()
    confine._apply_landlock(
        report,
        fs_read=None,
        fs_write=None,
        net_connect_ports=None,
        require_landlock=False,
    )
    assert any(item.startswith("landlock:") for item in report.skipped)


@requires_landlock
def test_policy_free_sandbox_reports_default_deny_filesystem():
    with iso.spawn("ll-default-deny", backend="process") as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert report is not None
        assert report["landlock"] is True
        assert report["landlock_default_deny_fs"] is True
        # The interpreter's own runtime paths are still granted, or the guest
        # could not import anything.
        assert report["landlock_rules"] >= 1


@requires_landlock
def test_sandbox_with_policy_paths_is_not_flagged_default_deny(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    policy = iso.policy.Policy().allow_fs(str(allowed))
    with iso.spawn("ll-policy-deny", policy=policy, backend="process") as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert report["landlock"] is True
        assert report["landlock_default_deny_fs"] is False


@live_landlock
def test_policy_free_sandbox_cannot_read_outside_the_interpreter(tmp_path):
    # The actual hole: with no policy, guest code that bypasses the Python open
    # guard used to read any host file. The interpreter's runtime paths stay
    # readable so the guest still works; a file outside them does not.
    secret = tmp_path / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    with iso.spawn("ll-default-read", backend="process") as sb:
        sb.exec(_REAL_READ.format(path=str(secret)))
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)


@live_landlock
def test_policy_free_sandbox_can_still_import_the_stdlib():
    # Default-deny is only correct if it does not break the interpreter.
    with iso.spawn(
        "ll-default-import", allowed_imports=["json"], backend="process"
    ) as sb:
        sb.exec("import json; post(json.dumps({'ok': True}))")
        assert sb.recv(timeout=5) == '{"ok": true}'


@live_landlock
def test_policy_free_sandbox_cannot_write_outside_the_interpreter(tmp_path):
    target = tmp_path / "written.txt"
    write_src = """
def _real_open(path, mode):
    for cls in ().__class__.__base__.__subclasses__():
        if cls.__name__ == "catch_warnings":
            return cls()._module.__builtins__["open"](path, mode)
    raise RuntimeError("no real open")
handle = _real_open({path!r}, "w")
handle.write("owned")
handle.close()
post("WROTE")
"""
    with iso.spawn("ll-default-write", backend="process") as sb:
        sb.exec(write_src.format(path=str(target)))
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)
    assert not target.exists()


class _FakeLibc:
    """Records the Landlock syscalls a real kernel would receive.

    Lets the default-deny ruleset construction be verified on hosts without
    Landlock (including CI runners on older kernels), where the live tests
    above can only skip.
    """

    def __init__(self):
        self.created_attrs = []
        self.path_rules = 0
        self.restricted = False

    def syscall(self, number, *args):
        if number == landlock._NR_LANDLOCK_CREATE_RULESET:
            attr_ref = args[0]
            self.created_attrs.append(attr_ref._obj.handled_access_fs)
            # A real fd, because apply_landlock closes it.
            return os.open(os.devnull, os.O_RDONLY)
        if number == landlock._NR_LANDLOCK_ADD_RULE:
            if args[1] == landlock._LANDLOCK_RULE_PATH_BENEATH:
                self.path_rules += 1
            return 0
        if number == landlock._NR_LANDLOCK_RESTRICT_SELF:
            self.restricted = True
            return 0
        raise AssertionError(f"unexpected syscall {number}")


def test_default_deny_builds_a_ruleset_granting_only_runtime_paths(monkeypatch):
    fake = _FakeLibc()
    monkeypatch.setattr(landlock, "abi_version", lambda: 1)
    monkeypatch.setattr(landlock, "_libc", lambda: fake)

    report = landlock.apply_landlock(None, None, default_deny_fs=True)

    # The filesystem access class is handled, which is what makes Landlock
    # deny every path not added as a rule.
    assert fake.created_attrs and fake.created_attrs[0] != 0
    # The interpreter's own runtime paths are granted, so the guest still runs.
    assert fake.path_rules == len(landlock._runtime_read_paths())
    assert fake.restricted is True
    assert report.applied is True
    assert report.default_deny_fs is True
    assert report.rules == fake.path_rules


def test_policy_paths_are_added_on_top_of_runtime_paths(monkeypatch, tmp_path):
    readable = tmp_path / "r"
    writable = tmp_path / "w"
    readable.mkdir()
    writable.mkdir()
    fake = _FakeLibc()
    monkeypatch.setattr(landlock, "abi_version", lambda: 1)
    monkeypatch.setattr(landlock, "_libc", lambda: fake)

    report = landlock.apply_landlock([str(readable)], [str(writable)])

    assert fake.path_rules == len(landlock._runtime_read_paths()) + 2
    # A policy was supplied, so this is policy confinement, not the bare default.
    assert report.default_deny_fs is False
