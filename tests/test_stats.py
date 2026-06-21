import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate.runtime import thread as thread_mod


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


def test_stats_tolerates_concurrent_start_time_reset(monkeypatch):
    # `stats` is read from other threads (the metrics scraper, the supervisor)
    # while the sandbox thread flips `_start_time` between a float and None in
    # its run loop. Snapshotting it must keep the computation from racing into
    # `monotonic() - None`, which raised TypeError and aborted the whole scrape.
    sb = object.__new__(thread_mod.SandboxThread)
    sb._cpu_time = 7.0
    sb._start_time = 123.0
    sb._mem_peak = 0
    sb._latency = {}
    sb._latency_sum = 0.0
    sb._errors = 0
    sb._ops = 0
    sb._denial_events = []

    # Emulate the run loop nulling `_start_time` *during* the stats computation:
    # the first `monotonic()` call inside `stats` resets it, exactly as a
    # concurrent reset on the sandbox thread would between the two reads.
    def resetting_monotonic():
        sb._start_time = None
        return 200.0

    monkeypatch.setattr(thread_mod.time, "monotonic", resetting_monotonic)

    # Must not raise. Before the fix this raised:
    #   TypeError: unsupported operand type(s) for -: 'float' and 'NoneType'
    result = sb.stats
    # The snapshotted start (123.0) is used rather than the reset None.
    assert result.cpu_ms == pytest.approx(7.0 + (200.0 - 123.0) * 1000)
