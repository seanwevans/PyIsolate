import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def test_stats_property_updates():
    sb = iso.spawn("stats")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        s = sb.stats
        assert s.cpu_ms >= 0
        assert s.mem_bytes >= 0
        assert s.io_bytes >= 0
        assert s.iops >= 0
    finally:
        sb.close()
