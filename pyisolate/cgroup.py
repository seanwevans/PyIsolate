"""Minimal cgroup v2 helper."""

from __future__ import annotations

import os
from pathlib import Path
import ctypes

__all__ = ["create", "attach_current", "delete"]

# Allow tests to override the base cgroup directory
_BASE = Path(os.environ.get("PYISOLATE_CGROUP_ROOT", "/sys/fs/cgroup")) / "pyisolate"


def _write(file: Path, val: str) -> None:
    try:
        file.write_text(val)
    except (OSError, PermissionError, FileNotFoundError):
        pass


def create(name: str, cpu_ms: int | None = None, mem_bytes: int | None = None) -> Path | None:
    """Create a cgroup and apply optional limits."""
    path = _BASE / name
    try:
        path.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError):
        return None

    if cpu_ms is not None:
        quota_us = cpu_ms * 1000
        _write(path / "cpu.max", f"{quota_us} 1000000")
    if mem_bytes is not None:
        _write(path / "memory.max", str(mem_bytes))
    return path


def attach_current(path: Path | None) -> None:
    """Move the current thread into the given cgroup."""
    if path is None:
        return
    if hasattr(os, "gettid"):
        tid = os.gettid()
    else:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        tid = libc.syscall(186)
    try:
        (path / "cgroup.threads").write_text(str(tid))
    except (OSError, PermissionError, FileNotFoundError):
        pass


def delete(path: Path | None) -> None:
    """Remove an empty cgroup."""
    if path is None:
        return
    try:
        for f in path.iterdir():
            f.unlink(missing_ok=True)
        path.rmdir()
    except (OSError, PermissionError, FileNotFoundError):
        pass
