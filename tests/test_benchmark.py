"""Smoke tests for scripts/benchmark.py (importability + summary stats).

The spawn/round-trip measurements are covered indirectly by the suite's
performance tests; here we only lock the script's importability and the pure
statistics helper so the benchmark does not silently bit-rot.
"""

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_benchmark():
    spec = importlib.util.spec_from_file_location(
        "pyisolate_benchmark", ROOT / "scripts" / "benchmark.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_summary_reports_expected_statistics():
    bench = _load_benchmark()
    summary = bench._summary([10.0, 20.0, 30.0, 40.0])
    assert summary["min"] == 10.0
    assert summary["max"] == 40.0
    assert summary["mean"] == 25.0
    assert summary["median"] == 25.0
    assert summary["p95"] >= summary["median"]


def test_benchmark_exposes_expected_entry_points():
    bench = _load_benchmark()
    assert callable(bench.bench_spawn)
    assert callable(bench.bench_roundtrip)
    assert callable(bench.main)
