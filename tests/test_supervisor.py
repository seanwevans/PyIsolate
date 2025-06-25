import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate.bpf.manager import BPFManager


def test_list_active_contains_spawned():
    sb = iso.spawn("active")
    try:
        active = iso.list_active()
        assert "active" in active
        assert isinstance(active["active"], iso.Sandbox)
    finally:
        sb.close()


def test_reload_policy_delegates(tmp_path, monkeypatch):
    called = {}

    def fake_hot_reload(self, path):
        called["path"] = path

    monkeypatch.setattr(BPFManager, "hot_reload", fake_hot_reload)
    p = tmp_path / "p.json"
    p.write_text("{}")
    iso.reload_policy(str(p))
    assert called["path"] == str(p)
