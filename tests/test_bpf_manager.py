import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.bpf.manager import BPFManager


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
    assert ["bpftool", "prog", "load", str(mgr._obj), "/sys/fs/bpf/dummy"] in calls
    assert [
        "bpftool",
        "prog",
        "load",
        str(mgr._filter_obj),
        "/sys/fs/bpf/syscall_filter",
    ] in calls
    assert [
        "bpftool",
        "prog",
        "load",
        str(mgr._guard_obj),
        "/sys/fs/bpf/resource_guard",
    ] in calls
    assert mgr.loaded


def test_load_lenient_mode_does_not_raise(monkeypatch):
    monkeypatch.setattr(
        BPFManager, "_run", lambda self, cmd, *, raise_on_error=False: True
    )
    mgr = BPFManager()

    mgr.load(strict=False)

    assert mgr.loaded


def test_hot_reload_updates_maps(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "subprocess.run", lambda *a, **k: subprocess.CompletedProcess([], 0)
    )
    mgr = BPFManager()
    mgr.load()

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"cpu": "100ms"}))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps["cpu"] == "100ms"

    policy.write_text(json.dumps({"cpu": "200ms", "mem": "64MiB"}))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps == {"cpu": "200ms", "mem": "64MiB"}


def test_hot_reload_handles_nested_policy(tmp_path, monkeypatch):
    calls = []

    def recorder(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", recorder)
    mgr = BPFManager()
    mgr.loaded = True

    policy = tmp_path / "policy.json"
    nested = {
        "sandboxes": {
            "default": {
                "fs": [{"action": "allow", "path": "/tmp/**"}],
                "tcp": [{"action": "connect", "addr": "1.1.1.1:80"}],
                "imports": ["math"],
            }
        }
    }
    policy.write_text(json.dumps(nested))

    mgr.hot_reload(str(policy))

    assert mgr.policy_maps == nested
    assert any("\"tcp\"" in cmd[-2] for cmd in calls)


def test_load_failure_logs_and_raises(monkeypatch, caplog):
    def fake_run(cmd, check, capture_output, text):
        if "bpftool" in cmd:
            raise subprocess.CalledProcessError(1, cmd, stderr="load boom")
        return subprocess.CompletedProcess(cmd, 0, "", "")


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


def test_hot_reload_failure_raises(monkeypatch, tmp_path, caplog):
    mgr = BPFManager()
    mgr.loaded = True
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"cpu": "100ms", "mem": "64MiB"}))

    def fake_run(cmd, check, capture_output, text):
        if "update" in cmd and any("cpu" in part for part in cmd):
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
    policy.write_text(json.dumps({"cpu": "100ms"}))
    caplog.set_level(logging.INFO)
    mgr.hot_reload(str(policy))
    assert any("cpu" in rec.getMessage() for rec in caplog.records)
