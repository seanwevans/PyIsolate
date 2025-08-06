import sys
import time
from pathlib import Path

import pytest

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
        assert s.cost >= 0
    finally:
        sb.close()


def test_cpu_ms_stops_after_failed_exec():
    sb = iso.spawn("stats-fail")
    try:
        sb.exec("raise ValueError('boom')")
        with pytest.raises(ValueError):
            sb.recv(timeout=0.5)
        first = sb.stats.cpu_ms
        time.sleep(0.05)
        second = sb.stats.cpu_ms
        assert second == pytest.approx(first, abs=0.1)
    finally:
        sb.close()
