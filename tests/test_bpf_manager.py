import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.bpf.manager import (
    BPF_KEY_BYTES,
    BPF_VALUE_BYTES,
    BPFManager,
    encode_map_field,
)


@pytest.fixture(autouse=True)
def _cold_skeleton_cache():
    """Give every test a cold ``_SKEL_CACHE``.

    The cache is shared class state, so another test -- or the supervisor
    singleton's real BPF ``load()`` -- can warm it with a compiled skeleton.
    When that happens ``load()`` legitimately skips the clang/bpftool build,
    which would defeat the tests that assert those toolchain commands run.
    """
    saved = BPFManager._SKEL_CACHE
    BPFManager._SKEL_CACHE = {}
    try:
        yield
    finally:
        BPFManager._SKEL_CACHE = saved


def _canonical_policy(*, fs_path="/tmp/**", tcp_addr="1.1.1.1:80"):
    return {
        "schema_version": "1.0",
        "semantics_version": 1,
        "sandboxes": {
            "default": {
                "allow_fs": [
                    {"action": "allow", "path": fs_path, "access": "readwrite"}
                ],
                "deny_fs": [],
                "allow_tcp": [{"action": "connect", "destination": tcp_addr}],
                "deny_tcp": [],
                "imports": ["math"],
            }
        },
        "deny_log": [],
    }


def test_encode_map_field_is_fixed_width_hex():
    encoded = encode_map_field("default:0", BPF_KEY_BYTES)
    assert len(encoded) == BPF_KEY_BYTES
    assert all(tok.startswith("0x") and len(tok) == 4 for tok in encoded)
    # Deterministic for the same input; distinct inputs differ.
    assert encode_map_field("default:0", BPF_KEY_BYTES) == encoded
    assert encode_map_field("default:1", BPF_KEY_BYTES) != encoded
    # The requested width is honored.
    assert len(encode_map_field("/tmp/**", BPF_VALUE_BYTES)) == BPF_VALUE_BYTES


def test_load_runs_toolchain(monkeypatch):
    calls = []

    def fake_run(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", fake_run)
    mgr = BPFManager()
    mgr.load()

    clang_dummy = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-c",
        str(mgr._src),
        "-o",
        str(mgr._obj),
    ]

    assert clang_dummy in calls
    skel_cmd = [
        "sh",
        "-c",
        f"bpftool gen skeleton {mgr._obj} > {mgr._skel}",
    ]
    assert skel_cmd in calls

    clang_filter = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-c",
        str(mgr._filter_src),
        "-o",
        str(mgr._filter_obj),
    ]
    clang_guard = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-c",
        str(mgr._guard_src),
        "-o",
        str(mgr._guard_obj),
    ]
    assert clang_dummy in calls
    assert clang_filter in calls
    assert clang_guard in calls
    assert ["llvm-objdump", "-d", str(mgr._obj)] in calls
    assert ["llvm-objdump", "-d", str(mgr._filter_obj)] in calls
    assert ["llvm-objdump", "-d", str(mgr._guard_obj)] in calls
    assert ["bpftool", "prog", "load", str(mgr._obj), str(mgr._dummy_pin)] in calls
    assert [
        "bpftool",
        "prog",
        "loadall",
        str(mgr._filter_obj),
        str(mgr._filter_pin_dir),
        "type",
        "lsm",
        "pinmaps",
        str(mgr._bpffs_root),
        "autoattach",
    ] in calls
    assert [
        "bpftool",
        "prog",
        "loadall",
        str(mgr._guard_obj),
        str(mgr._guard_pin_dir),
        "pinmaps",
        str(mgr._bpffs_root),
        "autoattach",
    ] in calls
    assert [
        "bpftool",
        "cgroup",
        "attach",
        "/sys/fs/cgroup",
        "egress",
        "pinned",
        str(mgr._guard_pin_dir / "account_cgroup_egress"),
    ] in calls
    assert mgr.loaded


def test_load_lenient_mode_does_not_raise(monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )
    mgr = BPFManager()

    mgr.load(strict=False)

    assert mgr.loaded


def test_generated_bpf_artifacts_use_configured_cache(tmp_path, monkeypatch):
    cache_dir = tmp_path / "bpf-cache"
    monkeypatch.setenv(BPFManager._CACHE_ENV, str(cache_dir))
    BPFManager._SKEL_CACHE.clear()

    calls = []

    def record(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr = BPFManager()
    mgr.load()

    package_dir = Path(BPFManager.__module__.replace(".", "/"))
    package_bpf_dir = ROOT / package_dir.parent
    output_paths = {mgr._obj, mgr._skel, mgr._filter_obj, mgr._guard_obj}

    assert output_paths == {
        cache_dir / "dummy.bpf.o",
        cache_dir / "dummy.skel.h",
        cache_dir / "syscall_filter.bpf.o",
        cache_dir / "resource_guard.bpf.o",
    }
    assert all(path.is_relative_to(cache_dir) for path in output_paths)
    assert not any(path.is_relative_to(package_bpf_dir) for path in output_paths)
    assert mgr._src == package_bpf_dir / "dummy.bpf.c"
    assert mgr._filter_src == package_bpf_dir / "syscall_filter.bpf.c"
    assert mgr._guard_src == package_bpf_dir / "resource_guard.bpf.c"

    command_text = "\n".join(" ".join(map(str, cmd)) for cmd in calls)
    assert str(cache_dir) in command_text
    assert str(package_bpf_dir / "dummy.bpf.o") not in command_text
    assert str(package_bpf_dir / "syscall_filter.bpf.o") not in command_text
    assert str(package_bpf_dir / "resource_guard.bpf.o") not in command_text


def test_cache_directory_creation_failure_is_descriptive(tmp_path, monkeypatch):
    cache_file = tmp_path / "not-a-directory"
    cache_file.write_text("not a directory")
    monkeypatch.setenv(BPFManager._CACHE_ENV, str(cache_file))

    with pytest.raises(RuntimeError) as exc:
        BPFManager()

    assert str(cache_file) in str(exc.value)
    assert "writable directory" in str(exc.value)


def test_hot_reload_updates_maps(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: subprocess.CompletedProcess([], 0)
    )
    mgr = BPFManager()
    mgr.load()

    policy = tmp_path / "policy.json"
    first = _canonical_policy(fs_path="/tmp/one/**", tcp_addr="1.1.1.1:80")
    policy.write_text(json.dumps(first))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps == first

    second = _canonical_policy(fs_path="/tmp/two/**", tcp_addr="1.1.1.1:443")
    policy.write_text(json.dumps(second))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps == second


def test_hot_reload_handles_nested_policy(tmp_path, monkeypatch):
    calls = []

    def recorder(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", recorder)
    mgr = BPFManager()
    mgr.loaded = True

    policy = tmp_path / "policy.json"
    nested = _canonical_policy()
    policy.write_text(json.dumps(nested))

    mgr.hot_reload(str(policy))

    assert mgr.policy_maps == nested
    assert [
        "bpftool",
        "map",
        "update",
        "pinned",
        "/sys/fs/bpf/policy_net_allow",
        "key",
        *encode_map_field("default:0", BPF_KEY_BYTES),
        "value",
        *encode_map_field("1.1.1.1:80", BPF_VALUE_BYTES),
        "any",
    ] in calls


def test_hot_reload_accepts_yaml_template(monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )
    mgr = BPFManager()
    mgr.loaded = True

    mgr.hot_reload(str(ROOT / "policy" / "readonly-fs.yml"))

    assert mgr.policy_maps["sandboxes"]["default"]["allow_fs"] == [
        {"action": "allow", "path": "/tmp", "access": "readwrite"}
    ]
    assert mgr.policy_maps["sandboxes"]["default"]["allow_tcp"] == []


def test_hot_reload_canonical_json_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )
    mgr = BPFManager()
    mgr.loaded = True
    policy = tmp_path / "canonical.json"
    expected = _canonical_policy(fs_path="/var/tmp/**", tcp_addr="127.0.0.1:443")
    policy.write_text(json.dumps(expected))

    mgr.hot_reload(str(policy))

    assert mgr.policy_maps == expected


def test_hot_reload_invalid_yaml_reports_runtime_error(tmp_path, monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )
    mgr = BPFManager()
    mgr.loaded = True
    bad = tmp_path / "bad.yml"
    bad.write_text("version: [not-a-supported-version\n")

    with pytest.raises(RuntimeError, match="Invalid policy data"):
        mgr.hot_reload(str(bad))


def test_load_failure_keeps_unloaded(monkeypatch, caplog):
    def fake_run(cmd, *_, **__):
        if "bpftool" in cmd:
            raise subprocess.CalledProcessError(1, cmd, stderr="load boom")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    mgr = BPFManager()
    caplog.set_level(logging.ERROR)
    with pytest.raises(RuntimeError) as exc:
        mgr.load(strict=True)
    assert "load boom" in str(exc.value)
    assert not mgr.loaded
    assert any("load boom" in rec.getMessage() for rec in caplog.records)


def test_load_skips_when_cached(monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )

    mgr = BPFManager()
    mgr.load()  # first load to populate cache

    calls = []

    def record(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr.load()  # cached

    compile_cmd = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-c",
        str(mgr._src),
        "-o",
        str(mgr._obj),
    ]
    skel_cmd = [
        "sh",
        "-c",
        f"bpftool gen skeleton {mgr._obj} > {mgr._skel}",
    ]

    assert compile_cmd not in calls
    assert skel_cmd not in calls


def test_load_compatibility_skips_strict_programs(monkeypatch):
    calls = []

    def record(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr = BPFManager()
    mgr.load(mode="compatibility")

    assert ["llvm-objdump", "-d", str(mgr._obj)] in calls
    assert [
        "bpftool",
        "prog",
        "load",
        str(mgr._obj),
        str(mgr._dummy_pin),
    ] in calls
    assert ["llvm-objdump", "-d", str(mgr._filter_obj)] not in calls
    assert ["llvm-objdump", "-d", str(mgr._guard_obj)] not in calls


def test_load_mode_hardened_sets_raise_on_error(monkeypatch):
    raise_flags = []

    def record(self, cmd, *, raise_on_error=False):
        raise_flags.append(raise_on_error)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr = BPFManager()
    mgr.load(mode="hardened")

    assert raise_flags
    assert all(raise_flags)


def test_hot_reload_failure_raises(monkeypatch, tmp_path, caplog):
    mgr = BPFManager()
    mgr.loaded = True
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(_canonical_policy()))

    def fake_run(cmd, check, capture_output, text):
        if "update" in cmd and any("policy_fs_allow" in part for part in cmd):
            raise subprocess.CalledProcessError(1, cmd, stderr="map boom")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    mgr = BPFManager()
    mgr.load()
    caplog.set_level(logging.ERROR)
    with pytest.raises(RuntimeError) as exc:
        mgr.hot_reload(str(policy))
    assert "map boom" in str(exc.value)
    assert any("map boom" in rec.getMessage() for rec in caplog.records)


def test_hot_reload_logs_updates(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: subprocess.CompletedProcess([], 0)
    )
    mgr = BPFManager()
    mgr.load()
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(_canonical_policy()))
    caplog.set_level(logging.INFO)
    mgr.hot_reload(str(policy))
    assert any("policy_fs_allow" in rec.getMessage() for rec in caplog.records)


@pytest.mark.parametrize("missing_tool", ["clang", "bpftool"])
def test_load_lenient_missing_executable_keeps_unloaded(
    monkeypatch, caplog, missing_tool
):
    def fake_run(cmd, check, capture_output, text):
        if cmd[0] == missing_tool or (
            missing_tool == "bpftool" and cmd[0] == "sh" and "bpftool" in cmd[2]
        ):
            raise FileNotFoundError(missing_tool)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    mgr = BPFManager()
    caplog.set_level(logging.ERROR)

    mgr.load(strict=False)

    assert mgr.loaded is False
    assert any(
        "command not found while running" in rec.getMessage() for rec in caplog.records
    )
    assert any(missing_tool in rec.getMessage() for rec in caplog.records)


@pytest.mark.parametrize("missing_tool", ["clang", "bpftool"])
def test_load_strict_missing_executable_raises_runtime_error(monkeypatch, missing_tool):
    def fake_run(cmd, check, capture_output, text):
        if cmd[0] == missing_tool or (
            missing_tool == "bpftool" and cmd[0] == "sh" and "bpftool" in cmd[2]
        ):
            raise FileNotFoundError(missing_tool)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("subprocess.run", fake_run)
    mgr = BPFManager()

    with pytest.raises(RuntimeError) as exc:
        mgr.load(strict=True)

    assert "Command not found" in str(exc.value)
    assert missing_tool in str(exc.value)
    assert mgr.loaded is False


def test_hot_reload_midway_failure_keeps_policy_maps_unchanged_and_rolls_back(
    monkeypatch, tmp_path
):
    mgr = BPFManager()
    mgr.loaded = True
    original = _canonical_policy(fs_path="/tmp/original/**", tcp_addr="1.1.1.1:80")
    mgr.policy_maps = original

    replacement = _canonical_policy(
        fs_path="/tmp/replacement/**", tcp_addr="2.2.2.2:443"
    )
    policy = tmp_path / "replacement.json"
    policy.write_text(json.dumps(replacement))

    calls = []

    def fail_second_update(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        if "policy_net_allow" in cmd[4]:
            raise RuntimeError("midway map failure")
        return True

    monkeypatch.setattr(BPFManager, "_run", fail_second_update)

    with pytest.raises(RuntimeError) as exc:
        mgr.hot_reload(str(policy))

    assert mgr.policy_maps == original
    assert "policy_net_allow[default:0]" in str(exc.value)
    assert "2.2.2.2:443" in str(exc.value)
    assert "after 1 successful update" in str(exc.value)
    assert [
        "bpftool",
        "map",
        "update",
        "pinned",
        "/sys/fs/bpf/policy_fs_allow",
        "key",
        *encode_map_field("default:0", BPF_KEY_BYTES),
        "value",
        *encode_map_field("/tmp/original/**", BPF_VALUE_BYTES),
        "any",
    ] in calls
