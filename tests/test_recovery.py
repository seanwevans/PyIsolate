import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import cgroup, recovery
from pyisolate.bpf.manager import BPFManager


def test_recover_tolerates_corrupt_registry(tmp_path, monkeypatch):
    reg = tmp_path / "registry.json"
    tmp_root = tmp_path / "tmp"

    monkeypatch.setattr(recovery, "_REGISTRY_PATH", reg)
    monkeypatch.setattr(recovery, "_TEMP_ROOT", tmp_root)

    reg.write_text("{broken", encoding="utf-8")
    assert recovery.recover() == {}

    normalized = json.loads(reg.read_text(encoding="utf-8"))
    assert normalized == {"sandboxes": {}}


def test_supervisor_recovery_cleans_stale_resources(tmp_path, monkeypatch):
    cgroup_root = tmp_path / "cgroup"
    reg = tmp_path / "registry.json"
    tmp_root = tmp_path / "tmp"

    monkeypatch.setattr(cgroup, "_BASE", cgroup_root / "pyisolate")
    monkeypatch.setattr(recovery, "_REGISTRY_PATH", reg)
    monkeypatch.setattr(recovery, "_TEMP_ROOT", tmp_root)

    def fake_load(self, *, mode="dev", strict=None):
        return None

    def fake_watchdog_start(self):
        return None

    def fake_watchdog_stop(self, timeout=0.2):
        return None

    monkeypatch.setattr(BPFManager, "load", fake_load)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.start", fake_watchdog_start)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.stop", fake_watchdog_stop)

    stale_cg = cgroup.create("stale")
    stale_tmp = recovery.allocate_temp_dir("stale")
    assert stale_cg is not None and stale_cg.exists()
    assert stale_tmp.exists()

    recovery.update_sandbox(
        "stale",
        {
            "name": "stale",
            "cgroup_path": str(stale_cg),
            "temp_dir": str(stale_tmp),
        },
    )

    sup = iso.Supervisor()
    try:
        assert recovery.recover() == {}
        assert not stale_cg.exists()
        assert not stale_tmp.exists()
    finally:
        sup.shutdown()


def test_cleanup_drops_registry_and_temp_dir_for_dead_sandbox(tmp_path, monkeypatch):
    cgroup_root = tmp_path / "cgroup"
    reg = tmp_path / "registry.json"
    tmp_root = tmp_path / "tmp"

    monkeypatch.setattr(cgroup, "_BASE", cgroup_root / "pyisolate")
    monkeypatch.setattr(recovery, "_REGISTRY_PATH", reg)
    monkeypatch.setattr(recovery, "_TEMP_ROOT", tmp_root)

    def fake_load(self, *, mode="dev", strict=None):
        return None

    def fake_watchdog_start(self):
        return None

    def fake_watchdog_stop(self, timeout=0.2):
        return None

    monkeypatch.setattr(BPFManager, "load", fake_load)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.start", fake_watchdog_start)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.stop", fake_watchdog_stop)

    sup = iso.Supervisor()
    try:
        sb = sup.spawn("dead")
        temp_dir = sb._thread._temp_dir
        assert temp_dir.exists()

        sb.close()
        sup._cleanup()

        assert "dead" not in recovery.recover()
        assert not temp_dir.exists()
    finally:
        sup.shutdown()
