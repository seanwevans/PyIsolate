import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate.observability.metrics import MetricsExporter


def test_export_contains_metrics():
    sb = iso.spawn("metrics")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        metrics = MetricsExporter().export()
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
    finally:
        for sb in sbs:
            sb.close()


def test_export_sanitizes_sandbox_name():
    name = 'weird "sand\\box\nname'
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
