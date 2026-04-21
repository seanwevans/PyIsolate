import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.bpf.manager import BPFManager


def test_module_import_is_lazy(monkeypatch):
    calls: list[str] = []

    def fake_load(self, *, mode="dev", strict=None):
        calls.append(f"load:{mode}:{strict}")

    def fake_watchdog_start(self):
        calls.append("watchdog")

    monkeypatch.setattr(BPFManager, "load", fake_load)
    monkeypatch.setattr("pyisolate.watchdog.ResourceWatchdog.start", fake_watchdog_start)

    sup_mod = iso.supervisor
    sup_mod._supervisor = None

    assert sup_mod._supervisor is None
    assert calls == []

    sup_mod.list_active()

    assert calls == ["load:dev:None", "watchdog"]
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


def test_supervisor_rollout_mode_passed_to_bpf(monkeypatch):
    seen = {}

    def fake_load(self, *, mode="dev", strict=None):
        seen["mode"] = mode
        seen["strict"] = strict

    monkeypatch.setattr(BPFManager, "load", fake_load)
    sup = iso.Supervisor(rollout_mode="compatibility")
    try:
        assert seen == {"mode": "compatibility", "strict": None}
    finally:
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


def test_cancel_kill_reap_lifecycle():
    sup = iso.Supervisor()
    try:
        sb = sup.spawn("life")
        assert sb.cancel(timeout=0.2) is True
        assert sb.kill(timeout=0.2) is True
        assert sb.reap() is True
    finally:
        sup.shutdown()


def test_quarantine_and_recycle():
    sup = iso.Supervisor()
    try:
        sb = sup.spawn("recover")
        sb.quarantine("wedged task")
        assert "recover" not in sup.list_active()
        revived = sup.spawn("recover")
        revived.exec("post('ok')")
        assert revived.recv(timeout=0.2) == "ok"
    finally:
        sup.shutdown()


def test_sandbox_termination_reason_passthrough():
    sup = iso.Supervisor()
    try:
        sb = sup.spawn("term", output_bytes_max=1)
        sb.exec("post('xx')")
        with pytest.raises(iso.OutputExceeded):
            sb.recv(timeout=0.5)
        assert sb.termination_reason == "output_exceeded"
    finally:
        sup.shutdown()


def test_tenant_quota_is_durable(tmp_path, monkeypatch):
    ledger = tmp_path / "quota.log"
    monkeypatch.setenv("PYISOLATE_QUOTA_LEDGER", str(ledger))

    sup1 = iso.Supervisor()
    try:
        sb = sup1.spawn("t1", tenant="acme", tenant_quota=1)
        sb.close()
    finally:
        sup1.shutdown()

    sup2 = iso.Supervisor()
    try:
        with pytest.raises(iso.TenantQuotaExceeded):
            sup2.spawn("t2", tenant="acme", tenant_quota=1)
    finally:
        sup2.shutdown()


def test_spawn_start_failure_rolls_back_tenant_usage_and_ledger(tmp_path, monkeypatch):
    ledger = tmp_path / "quota.log"
    monkeypatch.setenv("PYISOLATE_QUOTA_LEDGER", str(ledger))

    def fail_start(self):
        raise RuntimeError("start failed")

    monkeypatch.setattr("pyisolate.runtime.thread.SandboxThread.start", fail_start)

    sup = iso.Supervisor()
    try:
        with pytest.raises(RuntimeError, match="start failed"):
            sup.spawn("tenant-start-fail", tenant="acme", tenant_quota=1)
        assert sup._tenant_usage.get("acme", 0) == 0
    finally:
        sup.shutdown()

    assert ledger.read_text(encoding="utf-8").splitlines() == ["acme,1", "acme,-1"]

    sup_replay = iso.Supervisor()
    try:
        assert sup_replay._tenant_usage.get("acme", 0) == 0
    finally:
        sup_replay.shutdown()


def test_spawn_registry_failure_rolls_back_tenant_usage_and_ledger(tmp_path, monkeypatch):
    ledger = tmp_path / "quota.log"
    monkeypatch.setenv("PYISOLATE_QUOTA_LEDGER", str(ledger))

    def fail_update(*_args, **_kwargs):
        raise RuntimeError("registry update failed")

    monkeypatch.setattr("pyisolate.recovery.update_sandbox", fail_update)

    sup = iso.Supervisor()
    try:
        with pytest.raises(RuntimeError, match="registry update failed"):
            sup.spawn("tenant-registry-fail", tenant="acme", tenant_quota=1)
        assert sup._tenant_usage.get("acme", 0) == 0
        assert "tenant-registry-fail" not in sup._sandboxes
    finally:
        sup.shutdown()

    assert ledger.read_text(encoding="utf-8").splitlines() == ["acme,1", "acme,-1"]

    sup_replay = iso.Supervisor()
    try:
        assert sup_replay._tenant_usage.get("acme", 0) == 0
    finally:
        sup_replay.shutdown()
