import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.observability.metrics import MetricsExporter


def test_export_noop():
    MetricsExporter().export()
