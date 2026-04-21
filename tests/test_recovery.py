import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate import recovery


def test_recover_removes_stale_registry_and_temp_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(recovery, "REGISTRY_FILE", recovery.STATE_DIR / "registry.json")
    monkeypatch.setattr(recovery, "TEMP_ROOT", recovery.STATE_DIR / "sandboxes")

    stale_temp = recovery.allocate_temp_dir("stale")
    live_temp = recovery.allocate_temp_dir("live")
    recovery.update_sandbox("stale", {"temp_dir": str(stale_temp)})
    recovery.update_sandbox("live", {"temp_dir": str(live_temp)})

    recovery.recover(active_names={"live"})

    registry = recovery.load_registry()
    assert "live" in registry["sandboxes"]
    assert "stale" not in registry["sandboxes"]
    assert live_temp.exists()
    assert not stale_temp.exists()


def test_recover_tolerates_corrupt_registry(tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, "STATE_DIR", tmp_path / "state")
    monkeypatch.setattr(recovery, "REGISTRY_FILE", recovery.STATE_DIR / "registry.json")
    monkeypatch.setattr(recovery, "TEMP_ROOT", recovery.STATE_DIR / "sandboxes")
    recovery.STATE_DIR.mkdir(parents=True)
    recovery.REGISTRY_FILE.write_text("{broken")

    assert recovery.load_registry() == {"sandboxes": {}}
