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
    iso.set_policy_token("tok")
    iso.reload_policy(str(p), token="tok")
    assert called["path"] == str(p)


def test_shutdown_joins_threads():
    sup = iso.Supervisor()
    sb = sup.spawn("sd")
    sup.shutdown()
    assert not sup._watchdog.is_alive()
    assert not sb._thread.is_alive()


def test_spawn_uses_warm_pool():
    sup = iso.Supervisor(warm_pool=1)
    try:
        warm = sup._warm_pool[0]
        sb = sup.spawn("warm")
        assert sb._thread is warm
        assert len(sup._warm_pool) == 0
    finally:
        sb.close()
        sup.shutdown()


def test_shutdown_clears_warm_pool():
    sup = iso.Supervisor(warm_pool=1)
    assert len(sup._warm_pool) == 1
    sup.shutdown()
    assert sup._warm_pool == []
