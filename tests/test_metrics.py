import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import sys
import types


class _StubBPFManager:
    def __init__(self):
        self.loaded = False
        self.policy_maps = {}

    def load(self, strict: bool = False) -> None:  # pragma: no cover - stub
        self.loaded = False

    def hot_reload(self, policy_path: str) -> None:  # pragma: no cover - stub
        raise RuntimeError("BPF disabled")

    def _run(self, *_, **__):  # pragma: no cover - stub
        return True

    def open_ring_buffer(self):  # pragma: no cover - stub
        return iter(())


bpf_stub = types.ModuleType("pyisolate.bpf.manager")
bpf_stub.BPFManager = _StubBPFManager  # type: ignore[attr-defined]
sys.modules["pyisolate.bpf.manager"] = bpf_stub

import pyisolate as iso
from pyisolate.observability.metrics import MetricsExporter


def test_export_contains_metrics():
    sb = iso.spawn("metrics")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        assert "# HELP pyisolate_cpu_ms" in metrics
        assert "# TYPE pyisolate_cpu_ms gauge" in metrics
        assert "# HELP pyisolate_mem_bytes" in metrics
        assert "# TYPE pyisolate_mem_bytes gauge" in metrics
        assert "# HELP pyisolate_errors_total" in metrics
        assert "# TYPE pyisolate_errors_total counter" in metrics
        assert "# HELP pyisolate_cost" in metrics
        assert "# TYPE pyisolate_cost gauge" in metrics
        assert "# HELP pyisolate_latency_ms" in metrics
        assert "# TYPE pyisolate_latency_ms histogram" in metrics
        assert "# HELP pyisolate_cell_state" in metrics
        assert "# HELP pyisolate_quota_breaches_total" in metrics
        assert "# HELP pyisolate_policy_denials_total" in metrics
        assert "# HELP pyisolate_scheduler_latency_ms" in metrics
        assert "# HELP pyisolate_mem_hwm_bytes" in metrics
        assert "# HELP pyisolate_kill_latency_ms" in metrics
        assert "# HELP pyisolate_supervisor_health" in metrics
        assert "# HELP pyisolate_bpf_attachment_status" in metrics
        assert "pyisolate_cpu_ms" in metrics
        assert "pyisolate_mem_bytes" in metrics
        assert "pyisolate_errors_total" in metrics
        assert "pyisolate_latency_ms_bucket" in metrics
    finally:
        sb.close()


def test_export_sandbox_order_is_stable():
    sbs = [iso.spawn(name) for name in ["c", "a", "b"]]
    try:
        for sb in sbs:
            sb.exec("post(1)")
            sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
        order = [
            line.split('sandbox="')[1].split('"', 1)[0]
            for line in metrics.splitlines()
            if line.startswith("pyisolate_cpu_ms{")
        ]
        assert order == sorted(order)
        assert metrics.count("# HELP pyisolate_cpu_ms") == 1
        assert metrics.count("# TYPE pyisolate_cpu_ms gauge") == 1
        assert metrics.count("# HELP pyisolate_mem_bytes") == 1
        assert metrics.count("# TYPE pyisolate_mem_bytes gauge") == 1
        assert metrics.count("# HELP pyisolate_errors_total") == 1
        assert metrics.count("# TYPE pyisolate_errors_total counter") == 1
        assert metrics.count("# HELP pyisolate_cost") == 1
        assert metrics.count("# TYPE pyisolate_cost gauge") == 1
        assert metrics.count("# HELP pyisolate_latency_ms") == 1
        assert metrics.count("# TYPE pyisolate_latency_ms histogram") == 1
    finally:
        for sb in sbs:
            sb.close()


def test_export_sanitizes_sandbox_name():
    name = 'weird "sand\\box\nname'
    import re

    import pyisolate.supervisor as supervisor

    supervisor.NAME_PATTERN = re.compile(r".+", re.DOTALL)
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


def test_export_latency_bucket_order_and_cumulative_values(monkeypatch):
    import pyisolate.supervisor as supervisor

    class _FakeSandbox:
        def __init__(self):
            # Intentionally shuffled input ordering to ensure exporter order is
            # dictated by canonical bucket sequence.
            self.stats = types.SimpleNamespace(
                cell_id="cell-z",
                state="running",
                start_reason="spawn",
                stop_reason=None,
                cpu_ms=1.0,
                mem_bytes=64,
                mem_hwm_bytes=64,
                errors=0,
                policy_denials=0,
                quota_breaches={"cpu": 0, "memory": 0},
                scheduler_latency_ms_sum=0.3,
                scheduler_latency_samples=2,
                kill_latency_ms=0.0,
                operations=9,
                cost=0.1,
                latency={"10": 4, "0.5": 1, "inf": 5, "1": 2, "5": 3},
                latency_sum=17.5,
            )

    monkeypatch.setattr(supervisor, "list_active", lambda: {"sandbox-z": _FakeSandbox()})
    metrics = MetricsExporter().export()
    bucket_lines = [
        line
        for line in metrics.splitlines()
        if line.startswith('pyisolate_latency_ms_bucket{sandbox="sandbox-z"')
    ]
    assert len(bucket_lines) == 5
    assert bucket_lines[0].endswith('le="0.5"} 1')
    assert bucket_lines[1].endswith('le="1"} 3')
    assert bucket_lines[2].endswith('le="5"} 6')
    assert bucket_lines[3].endswith('le="10"} 10')
    assert bucket_lines[4].endswith('le="+Inf"} 15')


def test_export_latency_missing_buckets_default_to_zero(monkeypatch):
    import pyisolate.supervisor as supervisor

    class _FakeSandbox:
        def __init__(self):
            self.stats = types.SimpleNamespace(
                cell_id="cell-missing",
                state="running",
                start_reason="spawn",
                stop_reason=None,
                cpu_ms=1.0,
                mem_bytes=64,
                mem_hwm_bytes=64,
                errors=0,
                policy_denials=0,
                quota_breaches={"cpu": 0, "memory": 0},
                scheduler_latency_ms_sum=0.1,
                scheduler_latency_samples=1,
                kill_latency_ms=0.0,
                operations=1,
                cost=0.1,
                latency={"5": 1},
                latency_sum=5.0,
            )

    monkeypatch.setattr(
        supervisor, "list_active", lambda: {"sandbox-missing": _FakeSandbox()}
    )
    metrics = MetricsExporter().export()
    bucket_lines = [
        line
        for line in metrics.splitlines()
        if line.startswith('pyisolate_latency_ms_bucket{sandbox="sandbox-missing"')
    ]
    assert len(bucket_lines) == 5
    assert bucket_lines[0].endswith('le="0.5"} 0')
    assert bucket_lines[1].endswith('le="1"} 0')
    assert bucket_lines[2].endswith('le="5"} 1')
    assert bucket_lines[3].endswith('le="10"} 1')
    assert bucket_lines[4].endswith('le="+Inf"} 1')
