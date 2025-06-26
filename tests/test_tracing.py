import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.observability.trace import Tracer


def test_tracer_noop_span():
    tracer = Tracer("test")
    with tracer.start_span("demo"):
        pass
