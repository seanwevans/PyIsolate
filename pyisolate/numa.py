"""NUMA affinity helpers."""

from __future__ import annotations

import os
from typing import Set


def _parse_cpu_list(text: str) -> set[int]:
    """Parse Linux cpulist format like ``0-3,8``."""
    cpus: set[int] = set()
    for part in text.strip().split(","):
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-")
            start, end = int(start_str), int(end_str)
            cpus.update(range(start, end + 1))
        else:
            cpus.add(int(part))
    return cpus


def get_numa_cpus(node: int) -> Set[int]:
    """Return a set of CPU ids for the given NUMA node."""
    path = f"/sys/devices/system/node/node{node}/cpulist"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return set()
    return _parse_cpu_list(data)


def bind_current_thread(node: int) -> None:
    """Attempt to bind the current thread to the CPUs of ``node``."""
    cpus = get_numa_cpus(node)
    if not cpus:
        return
    try:
        os.sched_setaffinity(0, cpus)
    except (AttributeError, OSError):
        pass
