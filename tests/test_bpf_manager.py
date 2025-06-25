import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.bpf.manager import BPFManager


def test_load_runs_toolchain(monkeypatch):
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
    assert ["llvm-objdump", "-d", str(mgr._obj)] in calls
    assert ["bpftool", "prog", "load", str(mgr._obj), "/sys/fs/bpf/dummy"] in calls
    assert mgr.loaded


def test_hot_reload_updates_maps(tmp_path, monkeypatch):
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
    def fake_run(self, cmd):
        return False if "bpftool" in cmd else True

    monkeypatch.setattr(BPFManager, "_run", fake_run)
    mgr = BPFManager()
    mgr.load()
    assert not mgr.loaded
