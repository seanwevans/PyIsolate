"""Tests for scripts/cell_cost.py.

The measurements themselves are wall-clock dependent and are not asserted on.
What is worth locking down is the reporting contract the README quotes from,
and the version guard: the lifecycle rows destroy interpreters that have
imported a real module surface, which aborts the process on CPython 3.13's
private ``_interpreters``, so they must stay opt-in below 3.14.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_cell_cost():
    spec = importlib.util.spec_from_file_location(
        "pyisolate_cell_cost", ROOT / "scripts" / "cell_cost.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_summarize_reports_expected_statistics():
    cc = _load_cell_cost()
    summary = cc.summarize([10.0, 20.0, 30.0, 40.0])
    assert summary["min"] == 10.0
    assert summary["max"] == 40.0
    assert summary["median"] == 25.0
    assert summary["p95"] >= summary["median"]


def test_exposes_expected_entry_points():
    cc = _load_cell_cost()
    for name in (
        "measure_lifecycle",
        "measure_pool_dispatch",
        "measure_fork",
        "measure_parallel",
        "build_report",
        "main",
    ):
        assert callable(getattr(cc, name)), name


def test_lifecycle_gate_tracks_the_stable_api_version():
    """Below 3.14 the lifecycle rows must not run unless explicitly allowed."""
    cc = _load_cell_cost()
    assert cc.STABLE_INTERPRETERS_API == (3, 14)
    expected = sys.version_info[:2] >= cc.STABLE_INTERPRETERS_API
    assert cc.lifecycle_is_safe() is expected


def test_build_report_skips_lifecycle_on_an_unstable_api(monkeypatch):
    """The guard, not the Python actually running the tests, decides."""
    cc = _load_cell_cost()
    monkeypatch.setattr(cc, "lifecycle_is_safe", lambda: False)
    monkeypatch.setattr(cc, "measure_fork", lambda n: None)
    monkeypatch.setattr(cc, "measure_pool_dispatch", lambda n: {"median": 0.0})
    monkeypatch.setattr(cc, "measure_parallel", lambda w: {"workers": float(w)})

    def _must_not_run(_n):  # pragma: no cover - the point is that it is not called
        raise AssertionError("lifecycle rows ran on an unstable interpreters API")

    monkeypatch.setattr(cc, "measure_lifecycle", _must_not_run)

    report = cc.build_report(1, 1)
    assert report["lifecycle"] is None

    # ...and that the opt-out is what re-enables them.
    monkeypatch.setattr(cc, "measure_lifecycle", lambda n: [{"surface": "bare"}])
    forced = cc.build_report(1, 1, allow_unstable=True)
    assert forced["lifecycle"] == [{"surface": "bare"}]


def test_report_carries_the_fields_the_readme_quotes():
    cc = _load_cell_cost()
    if cc._IMPL is None:
        pytest.skip("no interpreters API on this build")
    report = cc.build_report(2, 2, allow_unstable=False)
    for key in (
        "python",
        "free_threaded",
        "interpreters_api",
        "fork_ms",
        "lifecycle",
        "pool_dispatch_ms",
        "parallel",
    ):
        assert key in report, key
    assert report["parallel"]["workers"] == 2.0
    assert report["pool_dispatch_ms"]["median"] >= 0.0


def test_print_report_handles_a_skipped_lifecycle(capsys):
    """The table renderer must not blow up on the guarded path."""
    cc = _load_cell_cost()
    cc.print_report(
        {
            "python": "3.13.0",
            "free_threaded": False,
            "interpreters_api": "_interpreters",
            "iterations": 5,
            "fork_ms": {"median": 1.0, "p95": 1.0, "min": 1.0, "max": 1.0},
            "lifecycle": None,
            "pool_dispatch_ms": {"median": 0.5, "p95": 0.6, "min": 0.4, "max": 0.7},
            "parallel": {
                "workers": 2.0,
                "sequential_ms": 2.0,
                "threads_ms": 2.0,
                "threads_speedup": 1.0,
                "cells_ms": 1.0,
                "cells_speedup": 2.0,
            },
        }
    )
    out = capsys.readouterr().out
    assert "lifecycle rows skipped" in out
    assert "--allow-unstable-api" in out
