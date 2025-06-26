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
        assert "pyisolate_io_bytes" in metrics
        assert "pyisolate_iops" in metrics
    finally:
        sb.close()
