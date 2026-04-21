import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.bpf.manager import BPFManager
from pyisolate.errors import TenantQuotaExceeded


def test_module_import_is_lazy(monkeypatch):
    calls: list[str] = []

    def fake_load(self):
        calls.append("load")

    def fake_watchdog_start(self):
        calls.append("watchdog")

    monkeypatch.setattr(BPFManager, "load", fake_load)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.start", fake_watchdog_start)

    sup_mod = iso.supervisor
    sup_mod._supervisor = None

    assert sup_mod._supervisor is None
    assert calls == []

    sup_mod.list_active()

    assert calls == ["load", "watchdog"]
    sup_mod._supervisor = None


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


def test_shutdown_requires_root():
    sup = iso.Supervisor()
    try:
        with pytest.raises(iso.PolicyAuthError):
            sup.shutdown(cap=iso.Token(name="user"))
    finally:
        # ensure resources cleaned up for subsequent tests
        sup.shutdown()


def test_spawn_invalid_name_empty():
    with pytest.raises(ValueError):
        iso.spawn("")


def test_spawn_invalid_name_long():
    with pytest.raises(ValueError):
        iso.spawn("x" * 65)


def test_spawn_invalid_name_type():
    with pytest.raises(ValueError):
        iso.spawn(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["valid-123", "under_score", "A-B_C"])
def test_spawn_valid_name_regex(name):
    sb = iso.spawn(name)
    try:
        assert sb._thread.name == name
    finally:
        sb.close()


@pytest.mark.parametrize("name", ["bad name", "name!", "foo/bar"])
def test_spawn_invalid_name_regex(name):
    with pytest.raises(ValueError):
        iso.spawn(name)


def test_spawn_duplicate_name_rejected():
    sup = iso.Supervisor()
    try:
        sb = sup.spawn("dup")
        with pytest.raises(RuntimeError, match="sandbox 'dup' already exists"):
            sup.spawn("dup")
        active = sup.list_active()
        assert "dup" in active
        assert active["dup"]._thread is sb._thread
    finally:
        sb.close()
        sup.shutdown()


def test_tenant_sustained_quota_blocks_new_spawn(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger.jsonl"
    monkeypatch.setenv("PYISOLATE_QUOTA_LEDGER", str(ledger))
    sup = iso.Supervisor()
    try:
        sb = sup.spawn("tenant-one", tenant="acme", tenant_quotas={"operations": 1})
        sb.exec("pass")
        sb.close()
        sup._cleanup()
        with pytest.raises(TenantQuotaExceeded):
            sup.spawn("tenant-two", tenant="acme", tenant_quotas={"operations": 1})
    finally:
        sup.shutdown()
