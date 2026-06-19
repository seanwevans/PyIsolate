"""Minimal cgroup v2 helper."""

from __future__ import annotations

import ctypes
import errno
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

__all__ = [
    "CgroupEnforcement",
    "create",
    "attach_current",
    "delete",
    "list_children",
    "cleanup_orphans",
]

# Allow tests to override the base cgroup directory
_BASE = Path(os.environ.get("PYISOLATE_CGROUP_ROOT", "/sys/fs/cgroup")) / "pyisolate"

log = logging.getLogger(__name__)

RolloutMode = Literal["dev", "compatibility", "hardened"]


@dataclass(frozen=True)
class CgroupEnforcement:
    """Result of creating a sandbox cgroup and installing quota controls.

    ``path`` is ``None`` only when the cgroup directory could not be created.
    ``cpu`` and ``memory`` indicate whether each requested controller accepted
    its limit.  ``errors`` contains human-readable diagnostics for degraded
    fallback modes so callers do not have to infer enforcement by checking for
    ``None``.
    """

    path: Path | None
    mode: str
    cpu: bool = False
    memory: bool = False
    errors: tuple[str, ...] = field(default_factory=tuple)

    @property
    def enforced(self) -> bool:
        """Return ``True`` when all requested cgroup controls were applied."""

        return self.path is not None and not self.errors

    def __bool__(self) -> bool:
        return self.path is not None

    def __fspath__(self) -> str:
        if self.path is None:
            raise TypeError("cgroup path is unavailable")
        return os.fspath(self.path)

    def __getattr__(self, name: str):
        if self.path is None:
            raise AttributeError(name)
        return getattr(self.path, name)


def _write(file: Path, val: str) -> bool:
    try:
        file.write_text(val)
        return True
    except (OSError, PermissionError, FileNotFoundError) as exc:
        log.warning("Failed to write %s: %s", file, exc)
        return False


def _failure(status: CgroupEnforcement, message: str) -> CgroupEnforcement:
    errors = (*status.errors, message)
    failed = CgroupEnforcement(
        path=status.path,
        mode=status.mode,
        cpu=status.cpu,
        memory=status.memory,
        errors=errors,
    )
    if status.mode == "hardened":
        raise RuntimeError(message)
    return failed


def create(
    name: str,
    cpu_ms: int | None = None,
    mem_bytes: int | None = None,
    *,
    mode: RolloutMode = "dev",
) -> CgroupEnforcement:
    """Create a cgroup and report which optional limits were enforced.

    In ``hardened`` mode, missing cgroup support or failed controller writes are
    fail-closed errors.  ``dev`` and ``compatibility`` modes return a degraded
    status object that callers can inspect and expose to operators.
    """

    if mode not in {"dev", "compatibility", "hardened"}:
        raise ValueError(f"invalid rollout mode: {mode}")

    path = _BASE / name
    try:
        path.mkdir(parents=True, exist_ok=True)
    except (OSError, PermissionError) as exc:
        msg = f"Failed to create cgroup {path}: {exc}"
        log.warning(msg)
        status = CgroupEnforcement(path=None, mode=mode)
        return _failure(status, msg)

    status = CgroupEnforcement(path=path, mode=mode)
    if cpu_ms is not None:
        quota_us = cpu_ms * 1000
        if _write(path / "cpu.max", f"{quota_us} 1000000"):
            status = CgroupEnforcement(
                path=status.path,
                mode=mode,
                cpu=True,
                memory=status.memory,
                errors=status.errors,
            )
        else:
            status = _failure(status, f"Failed to enforce CPU quota for {path}")
    if mem_bytes is not None:
        if _write(path / "memory.max", str(mem_bytes)):
            status = CgroupEnforcement(
                path=status.path,
                mode=mode,
                cpu=status.cpu,
                memory=True,
                errors=status.errors,
            )
        else:
            status = _failure(status, f"Failed to enforce memory quota for {path}")
    return status


def _as_path(path: Path | CgroupEnforcement | None) -> Path | None:
    if isinstance(path, CgroupEnforcement):
        return path.path
    return path


def attach_current(path: Path | CgroupEnforcement | None) -> None:
    """Move the current thread into the given cgroup.

    Uses :func:`threading.get_native_id` to determine the thread ID. For
    Python versions lacking this API, falls back to a raw ``syscall`` via
    ``ctypes``.
    """
    path = _as_path(path)
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


def delete(path: Path | CgroupEnforcement | None) -> None:
    """Remove a cgroup directory with best-effort thread drain."""
    path = _as_path(path)
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
            # Each TID migration is independent; one failure (e.g. a thread that
            # already exited) must not abandon draining the rest, or the cgroup
            # leaks. Keep going and rely on errno-aware rmdir logging below.
            continue

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
