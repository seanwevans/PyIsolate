"""Minimal cgroup v2 helper."""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import threading
from pathlib import Path

__all__ = ["create", "attach_current", "delete", "list_children", "cleanup_orphans"]

# Allow tests to override the base cgroup directory
_BASE = Path(os.environ.get("PYISOLATE_CGROUP_ROOT", "/sys/fs/cgroup")) / "pyisolate"

log = logging.getLogger(__name__)


def _write(file: Path, val: str) -> None:
    try:
        file.write_text(val)
    except (OSError, PermissionError, FileNotFoundError) as exc:
        log.warning("Failed to write %s: %s", file, exc)


def create(
    name: str, cpu_ms: int | None = None, mem_bytes: int | None = None
) -> Path | None:
    """Create a cgroup and apply optional limits."""
    path = _BASE / name
    try:
        path.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as exc:
        log.warning("Failed to create cgroup %s: %s", path, exc)
        return None

    if cpu_ms is not None:
        quota_us = cpu_ms * 1000
        _write(path / "cpu.max", f"{quota_us} 1000000")
    if mem_bytes is not None:
        _write(path / "memory.max", str(mem_bytes))
    return path


def attach_current(path: Path | None) -> None:
    """Move the current thread into the given cgroup.

    Uses :func:`threading.get_native_id` to determine the thread ID. For
    Python versions lacking this API, falls back to a raw ``syscall`` via
    ``ctypes``.
    """
    if path is None:
        return
    try:
        tid = threading.get_native_id()
    except AttributeError:  # Python < 3.8
        if hasattr(os, "gettid"):
            tid = os.gettid()
        else:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            tid = libc.syscall(186)
    try:
        (path / "cgroup.threads").write_text(str(tid))
    except (OSError, PermissionError, FileNotFoundError) as exc:
        log.warning("Failed to attach thread to %s: %s", path, exc)


def delete(path: Path | None) -> None:
    """Remove a cgroup directory with best-effort thread drain."""
    if path is None:
        return

    parent_threads = path.parent / "cgroup.threads"
    child_threads = path / "cgroup.threads"

    # Best-effort drain of lingering tasks so rmdir has a chance to succeed.
    try:
        tids = child_threads.read_text().splitlines()
    except (OSError, PermissionError, FileNotFoundError):
        tids = []

    for tid in tids:
        try:
            parent_threads.write_text(tid)
        except (OSError, PermissionError, FileNotFoundError):
            # Still attempt rmdir and rely on errno-aware logging below.
            break

    try:
        path.rmdir()
    except FileNotFoundError as exc:
        log.warning("Cgroup path missing while deleting %s: %s", path, exc)
    except PermissionError as exc:
        log.warning("Permission denied deleting cgroup %s: %s", path, exc)
    except OSError as exc:
        if exc.errno in {errno.EBUSY, errno.ENOTEMPTY}:
            log.warning("Cgroup %s is busy/non-empty; skipping delete: %s", path, exc)
        else:
            log.warning("Failed to delete cgroup %s: %s", path, exc)


def list_children() -> list[Path]:
    """List child cgroup directories under the pyisolate root."""
    if not _BASE.exists():
        return []
    try:
        return [p for p in _BASE.iterdir() if p.is_dir()]
    except (OSError, PermissionError, FileNotFoundError) as exc:
        log.warning("Failed to list cgroups under %s: %s", _BASE, exc)
        return []


def cleanup_orphans(active_names: set[str] | None = None) -> list[Path]:
    """Delete cgroups not present in *active_names*."""
    active = active_names or set()
    removed: list[Path] = []
    for child in list_children():
        if child.name in active:
            continue
        delete(child)
        removed.append(child)
    return removed
