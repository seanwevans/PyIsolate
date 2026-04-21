import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
import pyisolate.supervisor as supervisor_mod
from pyisolate.bpf.manager import BPFManager
from pyisolate.observability.metrics import MetricsExporter


def teardown_function():
    try:
        iso.shutdown()
    except Exception:
        pass


def _stub_bpf_load(monkeypatch):
    def fake_load(self, mode: str = "dev", strict: bool | None = None) -> None:
        self.loaded = True
        self.attachment_status = {
            "dummy": True,
            "resource_guard": False,
            "syscall_filter": True,
        }

    monkeypatch.setattr(BPFManager, "load", fake_load)


def test_export_contains_new_cell_metrics(monkeypatch):
    _stub_bpf_load(monkeypatch)
    sb = iso.spawn("metrics")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        assert "pyisolate_cell_state{" in metrics
        assert "pyisolate_mem_hwm_bytes{" in metrics
        assert "pyisolate_policy_denials_total{" in metrics
        assert "pyisolate_quota_breaches_total{" in metrics
        assert "pyisolate_scheduler_latency_ms_bucket{" in metrics
        assert "pyisolate_kill_latency_ms{" in metrics
        assert 'sandbox="metrics"' in metrics
        assert "cell_id=" in metrics
    finally:
        sb.close()


def test_export_contains_supervisor_and_bpf_metrics(monkeypatch):
    _stub_bpf_load(monkeypatch)
    sb = iso.spawn("super")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        assert "pyisolate_supervisor_health{" in metrics
        assert "pyisolate_bpf_attachment_status{" in metrics
        assert 'program="dummy"' in metrics
        assert 'program="resource_guard"} 0' in metrics
        assert 'program="syscall_filter"} 1' in metrics
    finally:
        sb.close()


def test_export_sandbox_order_is_stable(monkeypatch):
    _stub_bpf_load(monkeypatch)
    sbs = [iso.spawn(name) for name in ["c", "a", "b"]]
    try:
        for sb in sbs:
            sb.exec("post(1)")
            sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        order = [
            line.split('sandbox="')[1].split('"', 1)[0]
            for line in metrics.splitlines()
            if line.startswith("pyisolate_cell_state{")
        ]
        assert order == sorted(order)
    finally:
        for sb in sbs:
            sb.close()


def test_export_sanitizes_sandbox_name(monkeypatch):
    _stub_bpf_load(monkeypatch)
    import re

    name = 'weird "sand\\box\nname'
    supervisor_mod.NAME_PATTERN = re.compile(r".+", re.DOTALL)
    sb = iso.spawn(name)
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        escaped = name.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
        assert f'sandbox="{escaped}"' in metrics
        assert f'sandbox="{name}"' not in metrics
    finally:
        sb.close()
