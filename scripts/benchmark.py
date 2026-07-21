#!/usr/bin/env python3
"""Reproducible micro-benchmarks for PyIsolate on the current host.

Reports spawn latency and cell round-trip time for the sub-interpreter backend
(and, with ``--backend process``, the process backend). The numbers are
hardware-, kernel-, and build-dependent, so run this on your own machine rather
than trusting a headline figure copied from someone else's.

Usage::

    python scripts/benchmark.py
    python scripts/benchmark.py --backend process --iterations 500
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def bench_spawn(iterations: int, backend: str) -> list[float]:
    """Return per-op spawn+close wall times in milliseconds."""
    samples: list[float] = []
    for i in range(iterations):
        start = time.perf_counter()
        sb = iso.spawn(f"bench-spawn-{i}", backend=backend)
        sb.close()
        samples.append((time.perf_counter() - start) * 1e3)
    return samples


def bench_roundtrip(iterations: int, backend: str) -> list[float]:
    """Return per-op exec+recv round-trip times in microseconds."""
    samples: list[float] = []
    with iso.spawn("bench-rt", backend=backend) as sb:
        # Warm up so the first-call cost does not skew the distribution.
        sb.exec("post(1)")
        sb.recv(timeout=5)
        for _ in range(iterations):
            start = time.perf_counter()
            sb.exec("post(1)")
            sb.recv(timeout=5)
            samples.append((time.perf_counter() - start) * 1e6)
    return samples


def _summary(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    return {
        "mean": statistics.fmean(samples),
        "median": statistics.median(samples),
        "p95": p95,
        "min": ordered[0],
        "max": ordered[-1],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend",
        default="subinterpreter",
        choices=["subinterpreter", "process"],
        help="isolation backend to benchmark (default: subinterpreter)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=200,
        help="samples per benchmark (default: 200)",
    )
    args = parser.parse_args(argv)

    print(f"PyIsolate benchmark  backend={args.backend}  n={args.iterations}")
    print(f"python={sys.version.split()[0]}  platform={sys.platform}\n")

    spawn = _summary(bench_spawn(args.iterations, args.backend))
    rt = _summary(bench_roundtrip(args.iterations, args.backend))

    print(f"{'metric':<22}{'mean':>10}{'median':>10}{'p95':>10}")
    print(
        f"{'spawn latency (ms)':<22}"
        f"{spawn['mean']:>10.3f}{spawn['median']:>10.3f}{spawn['p95']:>10.3f}"
    )
    print(
        f"{'round-trip (us)':<22}"
        f"{rt['mean']:>10.1f}{rt['median']:>10.1f}{rt['p95']:>10.1f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
