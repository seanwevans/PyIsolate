import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.bpf.manager import BPFManager


def test_load_runs_toolchain(monkeypatch):
    BPFManager._SKEL_CACHE = {}
    calls = []

    def fake_run(self, cmd):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", fake_run)
    mgr = BPFManager()
    mgr.load()

    clang_call = [
        "clang",
        "-target",
        "bpf",
        "-O2",
        "-c",
        str(mgr._src),
        "-o",
        str(mgr._obj),
    ]
    assert clang_call in calls
    skel_cmd = [
        "sh",
        "-c",
        f"bpftool gen skeleton {mgr._obj} > {mgr._skel}",
    ]
    assert skel_cmd in calls
    assert ["llvm-objdump", "-d", str(mgr._obj)] in calls
    assert ["bpftool", "prog", "load", str(mgr._obj), "/sys/fs/bpf/dummy"] in calls
    assert mgr.loaded


def test_hot_reload_updates_maps(tmp_path, monkeypatch):
    BPFManager._SKEL_CACHE = {}
    monkeypatch.setattr("subprocess.run", lambda *a, **k: None)
    mgr = BPFManager()
    mgr.load()

    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"cpu": "100ms"}))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps["cpu"] == "100ms"

    policy.write_text(json.dumps({"cpu": "200ms", "mem": "64MiB"}))
    mgr.hot_reload(str(policy))
    assert mgr.policy_maps == {"cpu": "200ms", "mem": "64MiB"}


def test_load_failure_keeps_unloaded(monkeypatch):
    BPFManager._SKEL_CACHE = {}
    def fake_run(self, cmd):
        return False if "bpftool" in cmd else True

    monkeypatch.setattr(BPFManager, "_run", fake_run)
    mgr = BPFManager()
    mgr.load()
    assert not mgr.loaded


def test_load_skips_when_cached(monkeypatch):
    BPFManager._SKEL_CACHE = {}
    monkeypatch.setattr(BPFManager, "_run", lambda self, cmd: True)
    mgr = BPFManager()
    mgr.load()  # first load to populate cache

    calls = []

    def record(self, cmd):
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
