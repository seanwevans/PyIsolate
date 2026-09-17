#!/usr/bin/env python3
"""Measure what a sub-interpreter execution cell actually costs on this host.

``scripts/benchmark.py`` measures the *current* backends through the public
``iso.spawn`` API. This script measures the CPython primitives the planned
sub-interpreter backend would be built on, so the roadmap can be argued from
numbers taken on a real machine instead of from the assumption that a
sub-interpreter is cheap:

* ``create + exec + close`` for a fresh interpreter, at three import surfaces,
  because a sub-interpreter re-imports every module it uses and that import
  work -- not the interpreter object -- dominates the cost;
* resident memory held per live interpreter, for the same three surfaces;
* dispatch latency onto an already-warm pooled interpreter, which is the only
  regime where a cell is cheap;
* ``fork()`` of a warm parent, as the reference point: it is the boundary the
  process backend already gives you, so a cell that costs more than a fork is
  paying for isolation it does not provide;
* parallel scaling of cells against plain threads, which separates the two
  things free-threading and sub-interpreters actually buy -- parallelism comes
  from the free-threaded build, not from the interpreters.

Usage::

    python scripts/cell_cost.py
    python scripts/cell_cost.py --json
    python scripts/cell_cost.py --iterations 100

Requires CPython 3.12+ for ``_interpreters``; 3.14+ exposes the same thing as
the public ``concurrent.interpreters``. Run it on a free-threaded build to get
the parallel-scaling rows.

On CPython 3.13 the lifecycle rows are gated behind ``--allow-unstable-api``:
holding ~20 interpreters that have imported ``http.client`` or ``email.message``
and then destroying them aborts the process with ``munmap_chunk(): invalid
pointer``. The same workload is clean on 3.14's ``concurrent.interpreters``,
which is why the roadmap targets 3.14+ rather than the private module.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import threading
import time
from typing import Any, Callable, Optional

# --- interpreter API shim -------------------------------------------------
#
# 3.14 promoted the private ``_interpreters`` module to ``concurrent.interpreters``
# with an object API. Support both so the same numbers can be taken on 3.12/3.13
# and on 3.14+, which is the comparison the roadmap decision needs.

_IMPL: Optional[str]
try:  # pragma: no cover - exercised by whichever branch the host provides
    import concurrent.interpreters as _interp

    _IMPL = "concurrent.interpreters"
except ImportError:  # pragma: no cover - 3.12/3.13
    try:
        import _interpreters as _interp  # type: ignore[no-redef]

        _IMPL = "_interpreters"
    except ImportError:
        _interp = None  # type: ignore[assignment]
        _IMPL = None


class Cell:
    """One sub-interpreter, with create/exec/close spelled the same on 3.12+."""

    __slots__ = ("_id", "_obj")

    def __init__(self) -> None:
        if _IMPL == "concurrent.interpreters":
            self._obj = _interp.create()
            self._id = self._obj.id
        else:
            self._id = _interp.create()
            self._obj = None

    def exec(self, source: str) -> None:
        if self._obj is not None:
            self._obj.exec(source)
        else:
            _interp.run_string(self._id, source)

    def close(self) -> None:
        if self._obj is not None:
            self._obj.close()
        else:
            _interp.destroy(self._id)


# --- helpers --------------------------------------------------------------

BARE = "x = 1"
SMALL = "import json, re, dataclasses"
TYPICAL = "import json, re, dataclasses, email, http.client, logging, argparse"

SURFACES: tuple[tuple[str, str], ...] = (
    ("bare", BARE),
    ("json/re/dataclasses", SMALL),
    ("typical stdlib", TYPICAL),
)

CPU_WORK = (
    "def _f(n):\n"
    "    s = 0\n"
    "    for i in range(n):\n"
    "        s += i * i\n"
    "    return s\n"
    "_f(4_000_000)\n"
)


def rss_kib() -> int:
    """Resident set size of this process in KiB, or -1 where unavailable."""
    try:
        with open("/proc/self/status", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except OSError:
        pass
    return -1


def summarize(samples: list[float]) -> dict[str, float]:
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, int(len(ordered) * 0.95))
    return {
        "median": statistics.median(ordered),
        "p95": ordered[idx],
        "min": ordered[0],
        "max": ordered[-1],
    }


def time_ms(fn: Callable[[], None]) -> float:
    start = time.perf_counter()
    fn()
    return (time.perf_counter() - start) * 1e3


# --- measurements ---------------------------------------------------------


def measure_lifecycle(iterations: int) -> list[dict[str, Any]]:
    """create+exec, close, and held RSS for each import surface."""
    rows: list[dict[str, Any]] = []
    for label, body in SURFACES:
        cells: list[Cell] = []
        create: list[float] = []
        before = rss_kib()
        for _ in range(iterations):
            start = time.perf_counter()
            cell = Cell()
            cell.exec(body)
            create.append((time.perf_counter() - start) * 1e3)
            cells.append(cell)
        held = rss_kib()
        close: list[float] = []
        for cell in cells:
            close.append(time_ms(cell.close))
        rss_per_cell = (
            (held - before) / iterations if before >= 0 and held >= 0 else -1.0
        )
        rows.append(
            {
                "surface": label,
                "create_exec_ms": summarize(create),
                "close_ms": summarize(close),
                "rss_kib_per_cell": rss_per_cell,
            }
        )
    return rows


def measure_pool_dispatch(iterations: int, pool_size: int = 16) -> dict[str, float]:
    """Latency of running work on an interpreter that is already warm."""
    pool = [Cell() for _ in range(pool_size)]
    for cell in pool:
        cell.exec(SMALL)
    samples: list[float] = []
    for i in range(iterations):
        cell = pool[i % pool_size]
        samples.append(time_ms(lambda: cell.exec("y = sum(range(100))")))
    for cell in pool:
        cell.close()
    return summarize(samples)


def measure_fork(iterations: int) -> Optional[dict[str, float]]:
    """fork()+wait of a warm parent -- the reference boundary cost.

    Measured before any interpreter is created. ``fork()`` copies page tables,
    so its cost tracks the size of the parent's address space; forking after
    the lifecycle rows have churned through hundreds of interpreters measures
    that churn rather than the primitive, and overstates the fork by an order
    of magnitude.
    """
    if not hasattr(os, "fork"):
        return None
    exec(SMALL, {})  # warm the parent so the fork is pure copy-on-write
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        pid = os.fork()
        if pid == 0:  # pragma: no cover - child never returns
            os._exit(0)
        os.waitpid(pid, 0)
        samples.append((time.perf_counter() - start) * 1e3)
    return summarize(samples)


def measure_parallel(workers: int) -> dict[str, float]:
    """Speedup of N cells and of N plain threads over running N times in a row.

    The two rows together are the point: on a free-threaded build plain threads
    already scale, so sub-interpreters are not what buys parallelism. They buy a
    separate ``sys.modules`` and a separate set of globals per tenant.
    """

    def run_sequentially() -> None:
        for _ in range(workers):
            exec(CPU_WORK, {})  # noqa: S102 - the measured workload

    sequential = time_ms(run_sequentially)

    def run_threads() -> None:
        threads = [
            threading.Thread(target=exec, args=(CPU_WORK, {})) for _ in range(workers)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    threaded = time_ms(run_threads)

    pool = [Cell() for _ in range(workers)]
    for cell in pool:
        cell.exec("pass")

    def run_cells() -> None:
        threads = [threading.Thread(target=c.exec, args=(CPU_WORK,)) for c in pool]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    run_cells()  # warm: first exec in a cell pays for its own code objects
    celled = time_ms(run_cells)
    for cell in pool:
        cell.close()

    return {
        "workers": float(workers),
        "sequential_ms": sequential,
        "threads_ms": threaded,
        "threads_speedup": sequential / threaded if threaded else 0.0,
        "cells_ms": celled,
        "cells_speedup": sequential / celled if celled else 0.0,
    }


# --- reporting ------------------------------------------------------------


#: The lifecycle rows destroy many interpreters that have imported a realistic
#: module surface. That is exactly the pattern that aborts the process on the
#: private 3.13 API, so it is opt-in below 3.14 rather than a crash by default.
STABLE_INTERPRETERS_API = (3, 14)


def lifecycle_is_safe() -> bool:
    return sys.version_info[:2] >= STABLE_INTERPRETERS_API


def build_report(
    iterations: int, workers: int, *, allow_unstable: bool = False
) -> dict[str, Any]:
    # Order matters: fork() is measured first, on a parent that has not yet
    # created any interpreter, so it reports the primitive rather than the
    # address-space growth the later rows cause. See measure_fork.
    fork = measure_fork(iterations)
    run_lifecycle = lifecycle_is_safe() or allow_unstable
    return {
        "python": sys.version.split()[0],
        "free_threaded": not getattr(sys, "_is_gil_enabled", lambda: True)(),
        "interpreters_api": _IMPL,
        "iterations": iterations,
        "fork_ms": fork,
        "lifecycle": measure_lifecycle(iterations) if run_lifecycle else None,
        "pool_dispatch_ms": measure_pool_dispatch(iterations),
        "parallel": measure_parallel(workers),
    }


def print_report(report: dict[str, Any]) -> None:
    gil = "free-threaded" if report["free_threaded"] else "GIL enabled"
    print(
        f"PyIsolate cell cost   python={report['python']} ({gil})  "
        f"api={report['interpreters_api']}  n={report['iterations']}\n"
    )

    lifecycle = report["lifecycle"]
    if lifecycle is None:
        print(
            "lifecycle rows skipped: destroying interpreters that imported a real\n"
            "module surface aborts the process on this build's private API.\n"
            f"Re-run on CPython {STABLE_INTERPRETERS_API[0]}.{STABLE_INTERPRETERS_API[1]}+, "
            "or pass --allow-unstable-api to measure anyway."
        )
    else:
        print(f"{'import surface':<22}{'create+exec':>14}{'close':>10}{'RSS/cell':>12}")
        print(f"{'':<22}{'p50 ms':>14}{'p50 ms':>10}{'KiB':>12}")
        for row in lifecycle:
            create = row["create_exec_ms"]["median"]
            close = row["close_ms"]["median"]
            rss = row["rss_kib_per_cell"]
            print(f"{row['surface']:<22}{create:>14.2f}{close:>10.2f}{rss:>12.0f}")

    pool = report["pool_dispatch_ms"]
    print(f"\n{'dispatch onto warm cell':<22}{pool['median']:>14.3f}{'':>10}{'':>12}")
    fork = report["fork_ms"]
    if fork is not None:
        print(f"{'fork() of warm parent':<22}{fork['median']:>14.3f}")

    par = report["parallel"]
    print(
        f"\nparallel scaling at {int(par['workers'])} workers:  "
        f"threads {par['threads_speedup']:.2f}x   cells {par['cells_speedup']:.2f}x"
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--iterations",
        type=int,
        default=50,
        help="samples per measurement (default: 50)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="concurrent workers for the scaling rows (default: min(4, cpus))",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit JSON instead of a table"
    )
    parser.add_argument(
        "--allow-unstable-api",
        action="store_true",
        help=(
            "run the lifecycle rows on a pre-3.14 build, where destroying "
            "interpreters that imported http.client or email.message is known "
            "to abort the process"
        ),
    )
    args = parser.parse_args(argv)

    if _IMPL is None:
        print(
            "no interpreters API on this build: needs CPython 3.12+ for "
            "_interpreters, or 3.14+ for concurrent.interpreters",
            file=sys.stderr,
        )
        return 2

    report = build_report(
        args.iterations, args.workers, allow_unstable=args.allow_unstable_api
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
