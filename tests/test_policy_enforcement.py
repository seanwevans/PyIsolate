import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy


def test_policy_import_and_fs(tmp_path):
    p = (
        policy.Policy()
        .allow_import("math")
        .allow_import("pathlib")
        .allow_fs(str(tmp_path))
    )
    f = tmp_path / "data.txt"
    f.write_text("ok")

    sb = iso.spawn("pifs", policy=p)
    try:
        sb.exec("import math; post(math.sqrt(16))")
        assert sb.recv(timeout=1) == 4.0

        sb.exec(f"import pathlib; post(pathlib.Path({str(f)!r}).read_text())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec("import random")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec("import pathlib; post(pathlib.Path('/etc/hosts').read_text())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_fs_sibling_not_allowed(tmp_path):
    allowed_dir = tmp_path / "foo"
    allowed_dir.mkdir()
    (allowed_dir / "data.txt").write_text("ok")

    sibling_dir = tmp_path / "foobar"
    sibling_dir.mkdir()
    bad_file = sibling_dir / "data.txt"
    bad_file.write_text("nope")

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-sibling", policy=p)
    try:
        sb.exec(f"post(open({str((allowed_dir / 'data.txt').resolve())!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec(f"post(open({str(bad_file.resolve())!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_fs_allows_creating_new_files(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()

    allowed_target = allowed_dir / "new.txt"
    blocked_target = blocked_dir / "blocked.txt"

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-create", policy=p)
    try:
        sb.exec(
            (
                f"path = {str(allowed_target)!r}\n"
                "with open(path, 'w') as fh:\n"
                "    fh.write('hello world')\n"
                "with open(path) as fh:\n"
                "    post(fh.read())\n"
            )
        )
        assert sb.recv(timeout=1) == "hello world"

        sb.exec(
            (
                f"path = {str(blocked_target)!r}\n"
                "with open(path, 'w') as fh:\n"
                "    fh.write('nope')\n"
            )
        )
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    assert allowed_target.read_text() == "hello world"
    assert not blocked_target.exists()


def test_pathlib_path_read_text_respects_fs_policy(tmp_path):
    allowed_file = tmp_path / "allowed.txt"
    allowed_file.write_text("ok")

    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()
    blocked_file = blocked_dir / "blocked.txt"
    blocked_file.write_text("nope")

    p = policy.Policy().allow_import("pathlib").allow_fs(str(tmp_path))
    sb = iso.spawn("pifs-pathlib-read-text", policy=p)
    try:
        sb.exec(
            (
                "import pathlib\n"
                f"post(pathlib.Path({str(allowed_file)!r}).read_text())\n"
            )
        )
        assert sb.recv(timeout=1) == "ok"

        sb.exec(
            (
                "import pathlib\n"
                f"post(pathlib.Path({str(blocked_file)!r}).read_text())\n"
            )
        )
        assert sb.recv(timeout=1) == "nope"

        sb.exec(("import pathlib\n" "post(pathlib.Path('/etc/hosts').read_text())\n"))
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


@pytest.mark.parametrize(
    ("name", "source", "imports"),
    [
        ("os-open", "import os; os.open('/etc/hosts', os.O_RDONLY)", ["os"]),
        ("os-system", "import os; os.system('true')", ["os"]),
        ("os-exec", "import os; os.execve('/bin/true', ['true'], {})", ["os"]),
        ("os-spawn", "import os; os.spawnvp(os.P_WAIT, 'true', ['true'])", ["os"]),
        (
            "subprocess-popen",
            "import subprocess; subprocess.Popen(['true'])",
            ["subprocess"],
        ),
        (
            "socket-create-connection",
            "import socket; socket.create_connection(('127.0.0.1', 9), timeout=0.01)",
            ["socket"],
        ),
        (
            "socket-raw",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW)",
            ["socket"],
        ),
        ("ctypes-import", "import ctypes", ["ctypes"]),
        ("multiprocessing-import", "import multiprocessing", ["multiprocessing"]),
    ],
)
def test_policy_blocks_side_effect_import_escape_surfaces(name, source, imports):
    p = policy.Policy()
    for module in imports:
        p.allow_import(module)
    sb = iso.spawn(f"policy-{name}", policy=p)
    try:
        sb.exec(source)
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_fs_policy_blocks_symlink_escape_reads(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    link = allowed_dir / "escape.txt"
    link.symlink_to(outside)

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-symlink-read", policy=p)
    try:
        sb.exec(f"post(open({str(link)!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def _assert_denial_event(events, *, cell, capability, attempted_action, policy_rule):
    assert events
    event = events[-1]
    assert event["cell"] == cell
    assert event["capability"] == capability
    assert event["attempted_action"] == attempted_action
    assert event["policy_rule"] == policy_rule
    assert event["broker_decision"] == "deny"


def test_authority_filesystem_denial_records_event(tmp_path):
    allowed_dir = tmp_path / "allowed"
    denied_dir = tmp_path / "denied"
    allowed_dir.mkdir()
    denied_dir.mkdir()
    denied_file = denied_dir / "secret.txt"
    denied_file.write_text("nope")

    sb = iso.spawn(
        "authority-fs-denial", policy=policy.Policy().allow_read(str(allowed_dir))
    )
    try:
        denied_path = denied_file.resolve(strict=False)
        sb.exec(f"open({str(denied_path)!r}).read()")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="authority-fs-denial",
            capability="filesystem",
            attempted_action=f"open:{denied_path}",
            policy_rule="authority:read_path",
        )
    finally:
        sb.close()


def test_authority_network_denial_records_event():
    sb = iso.spawn(
        "authority-net-denial",
        policy=policy.Policy(
            capabilities=[iso.ConnectTCP("127.0.0.1", 1), iso.Import("socket")]
        ),
    )
    try:
        sb.exec("import socket; s=socket.socket(); s.connect(('127.0.0.1', 2))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="authority-net-denial",
            capability="network",
            attempted_action="connect:127.0.0.1:2",
            policy_rule="authority:connect_tcp",
        )
    finally:
        sb.close()


def test_fs_policy_blocks_symlink_escape_writes(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("unchanged")
    link = allowed_dir / "escape.txt"
    link.symlink_to(outside)

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-symlink-write", policy=p)
    try:
        sb.exec(f"open({str(link)!r}, 'w').write('changed')")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    assert outside.read_text() == "unchanged"


def test_safe_brokered_open_blocks_final_component_replacement_race(
    tmp_path, monkeypatch
):
    import pyisolate.runtime.thread as thread_mod

    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    target = allowed_dir / "target.txt"
    target.write_text("safe")
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")

    original_os_open = thread_mod.os.open
    replaced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if path == "target.txt" and dir_fd is not None and not replaced:
            replaced = True
            target.unlink()
            target.symlink_to(outside)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(thread_mod.os, "open", racing_open)

    with pytest.raises(iso.PolicyError):
        thread_mod._safe_brokered_open(target, "r", allowed_roots=(allowed_dir,))
    assert replaced


def test_runtime_policy_allow_fs_blocks_symlink_escape_reads(tmp_path):
    allowed_dir = tmp_path / "runtime-allowed"
    allowed_dir.mkdir()
    outside = tmp_path / "runtime-outside.txt"
    outside.write_text("secret")
    link = allowed_dir / "escape.txt"
    link.symlink_to(outside)

    runtime_policy = policy.RuntimePolicy(
        allow_fs=(policy.FilesystemRule("allow", str(allowed_dir)),),
    )
    sb = iso.spawn("runtime-fs-symlink-read", policy=runtime_policy)
    try:
        sb.exec(f"post(open({str(link)!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_runtime_policy_allow_fs_blocks_final_component_replacement_race(
    tmp_path, monkeypatch
):
    import pyisolate.runtime.thread as thread_mod

    allowed_dir = tmp_path / "runtime-allowed"
    allowed_dir.mkdir()
    target = allowed_dir / "target.txt"
    target.write_text("safe")
    outside = tmp_path / "runtime-outside.txt"
    outside.write_text("secret")

    original_os_open = thread_mod.os.open
    replaced = False

    def racing_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if path == "target.txt" and dir_fd is not None and not replaced:
            replaced = True
            target.unlink()
            target.symlink_to(outside)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(thread_mod.os, "open", racing_open)

    runtime_policy = policy.RuntimePolicy(
        allow_fs=(policy.FilesystemRule("allow", str(allowed_dir)),),
    )
    sb = iso.spawn("runtime-fs-symlink-swap", policy=runtime_policy)
    try:
        sb.exec(f"post(open({str(target)!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()
    assert replaced


def test_runtime_policy_deny_fs_preempts_filesystem_capability_allow(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    allowed_file = allowed_dir / "allowed.txt"
    allowed_file.write_text("ok")
    denied_file = allowed_dir / "secret.txt"
    denied_file.write_text("nope")
    denied_path = denied_file.resolve(strict=False)

    runtime_policy = policy.RuntimePolicy(
        allow_fs=(policy.FilesystemRule("allow", str(allowed_dir)),),
        deny_fs=(policy.FilesystemRule("deny", str(denied_file)),),
    )

    sb = iso.spawn(
        "runtime-deny-preempts-fs-cap",
        policy=runtime_policy,
        capabilities={"filesystem": iso.FilesystemCapability.from_paths(allowed_dir)},
    )
    try:
        sb.exec(f"post(open({str(allowed_file)!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec(f"open({str(denied_path)!r}).read()")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="runtime-deny-preempts-fs-cap",
            capability="filesystem",
            attempted_action=f"open:{denied_path}",
            policy_rule="runtime_policy:deny_fs",
        )
    finally:
        sb.close()

def test_runtime_policy_filesystem_deny_rule_records_event(tmp_path):
    allowed_dir = tmp_path / "allowed"
    denied_dir = tmp_path / "denied"
    allowed_dir.mkdir()
    denied_dir.mkdir()
    denied_file = denied_dir / "secret.txt"
    denied_file.write_text("nope")
    denied_path = denied_file.resolve(strict=False)

    runtime_policy = policy.RuntimePolicy(
        allow_fs=(policy.FilesystemRule("allow", str(tmp_path)),),
        deny_fs=(policy.FilesystemRule("deny", str(denied_dir)),),
    )
    sb = iso.spawn("runtime-fs-deny-rule", policy=runtime_policy)
    try:
        sb.exec(f"open({str(denied_path)!r}).read()")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="runtime-fs-deny-rule",
            capability="filesystem",
            attempted_action=f"open:{denied_path}",
            policy_rule="runtime_policy:deny_fs",
        )
    finally:
        sb.close()


def test_runtime_policy_filesystem_missing_allow_rule_records_event(tmp_path):
    allowed_dir = tmp_path / "allowed"
    denied_dir = tmp_path / "denied"
    allowed_dir.mkdir()
    denied_dir.mkdir()
    denied_file = denied_dir / "secret.txt"
    denied_file.write_text("nope")
    denied_path = denied_file.resolve(strict=False)

    runtime_policy = policy.RuntimePolicy(
        allow_fs=(policy.FilesystemRule("allow", str(allowed_dir)),),
    )
    sb = iso.spawn("runtime-fs-missing-allow", policy=runtime_policy)
    try:
        sb.exec(f"open({str(denied_path)!r}).read()")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="runtime-fs-missing-allow",
            capability="filesystem",
            attempted_action=f"open:{denied_path}",
            policy_rule="runtime_policy:allow_fs",
        )
    finally:
        sb.close()


def test_runtime_policy_network_deny_rule_records_event():
    runtime_policy = policy.RuntimePolicy(
        allow_tcp=(policy.NetworkRule("connect", "127.0.0.1:2"),),
        deny_tcp=(policy.NetworkRule("deny", "127.0.0.1:2"),),
        imports=("socket",),
    )
    sb = iso.spawn("runtime-net-deny-rule", policy=runtime_policy)
    try:
        sb.exec("import socket; s=socket.socket(); s.connect(('127.0.0.1', 2))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="runtime-net-deny-rule",
            capability="network",
            attempted_action="connect:127.0.0.1:2",
            policy_rule="runtime_policy:deny_tcp",
        )
    finally:
        sb.close()


def test_runtime_policy_network_missing_allow_rule_records_event():
    runtime_policy = policy.RuntimePolicy(
        allow_tcp=(policy.NetworkRule("connect", "127.0.0.1:1"),),
        imports=("socket",),
    )
    sb = iso.spawn("runtime-net-missing-allow", policy=runtime_policy)
    try:
        sb.exec("import socket; s=socket.socket(); s.connect(('127.0.0.1', 2))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        _assert_denial_event(
            sb.get_denial_events(),
            cell="runtime-net-missing-allow",
            capability="network",
            attempted_action="connect:127.0.0.1:2",
            policy_rule="runtime_policy:allow_tcp",
        )
    finally:
        sb.close()


def test_compiled_read_filesystem_rule_allows_reads_only(tmp_path):
    readable_dir = tmp_path / "readable"
    readable_dir.mkdir()
    readable_file = readable_dir / "data.txt"
    readable_file.write_text("ok")

    runtime_policy = policy.from_sandbox_policy(
        policy.compiler.SandboxPolicy(
            fs=[policy.compiler.FSRule("read", str(readable_dir))],
            tcp=[],
            imports=[],
            capabilities=[],
        )
    )

    sb = iso.spawn("compiled-fs-read", policy=runtime_policy)
    try:
        sb.exec(f"post(open({str(readable_file)!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec(f"open({str(readable_file)!r}, 'w').write('blocked')")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        assert readable_file.read_text() == "ok"
    finally:
        sb.close()


def test_compiled_write_filesystem_rule_allows_writes_only(tmp_path):
    writable_dir = tmp_path / "writable"
    writable_dir.mkdir()
    writable_file = writable_dir / "data.txt"
    writable_file.write_text("old")

    runtime_policy = policy.from_sandbox_policy(
        policy.compiler.SandboxPolicy(
            fs=[policy.compiler.FSRule("write", str(writable_dir))],
            tcp=[],
            imports=[],
            capabilities=[],
        )
    )

    sb = iso.spawn("compiled-fs-write", policy=runtime_policy)
    try:
        sb.exec(
            f"with open({str(writable_file)!r}, 'w') as fh:\n"
            "    post(fh.write('new'))"
        )
        assert sb.recv(timeout=1) == 3
        assert writable_file.read_text() == "new"

        sb.exec(f"post(open({str(writable_file)!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()
