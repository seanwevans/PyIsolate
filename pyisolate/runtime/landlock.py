"""Landlock filesystem confinement for ``backend="process"`` guest processes.

Landlock lets an unprivileged process irrevocably restrict its own filesystem
access to an allow-list of path hierarchies, enforced by the kernel.  Applied to
a guest process (which already has ``PR_SET_NO_NEW_PRIVS`` set by
:mod:`pyisolate.runtime.confine`), it turns the sandbox's filesystem policy into
a real kernel boundary: even guest code that defeats the Python ``open`` guard
and reaches the libc ``open``/``openat`` can only touch permitted paths.

Landlock is default-deny for every access right the ruleset *handles*: once a
ruleset handling ``READ_FILE``/``WRITE_FILE``/... is applied, those actions are
denied everywhere except beneath the paths added as rules.  So the guest must be
granted read+execute on the Python installation and system libraries it needs to
keep running, in addition to the policy's own read/write paths.

The set of access rights and struct layout depend on the kernel's Landlock ABI
version, which this module queries and masks against; requesting an unsupported
right makes ``landlock_create_ruleset`` fail.  Landlock is Linux-specific and
unavailable on many kernels (``landlock_create_ruleset`` returns ``ENOSYS``);
callers must treat :func:`landlock_supported` as authoritative.
"""

from __future__ import annotations

import ctypes
import os
import sys
from dataclasses import dataclass, field

# Landlock syscall numbers (x86-64).
_NR_LANDLOCK_CREATE_RULESET = 444
_NR_LANDLOCK_ADD_RULE = 445
_NR_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_RULE_PATH_BENEATH = 1

# Filesystem access rights (bit positions are a stable kernel ABI).
ACCESS_FS = {
    "EXECUTE": 1 << 0,
    "WRITE_FILE": 1 << 1,
    "READ_FILE": 1 << 2,
    "READ_DIR": 1 << 3,
    "REMOVE_DIR": 1 << 4,
    "REMOVE_FILE": 1 << 5,
    "MAKE_CHAR": 1 << 6,
    "MAKE_DIR": 1 << 7,
    "MAKE_REG": 1 << 8,
    "MAKE_SOCK": 1 << 9,
    "MAKE_FIFO": 1 << 10,
    "MAKE_BLOCK": 1 << 11,
    "MAKE_SYM": 1 << 12,
    "REFER": 1 << 13,  # ABI >= 2
    "TRUNCATE": 1 << 14,  # ABI >= 3
    "IOCTL_DEV": 1 << 15,  # ABI >= 5
}

_READ = ACCESS_FS["READ_FILE"] | ACCESS_FS["READ_DIR"]
_READ_EXEC = _READ | ACCESS_FS["EXECUTE"]
_WRITE = (
    _READ
    | ACCESS_FS["WRITE_FILE"]
    | ACCESS_FS["MAKE_REG"]
    | ACCESS_FS["MAKE_DIR"]
    | ACCESS_FS["MAKE_SYM"]
    | ACCESS_FS["REMOVE_FILE"]
    | ACCESS_FS["REMOVE_DIR"]
    | ACCESS_FS["TRUNCATE"]
)


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    # ``struct landlock_path_beneath_attr`` is packed: no padding between the
    # 8-byte access mask and the 4-byte fd.
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


@dataclass
class LandlockReport:
    """Outcome of applying Landlock to the current process."""

    applied: bool = False
    abi: int = 0
    rules: int = 0
    skipped: str | None = None
    denied_paths: list[str] = field(default_factory=list)


def _libc() -> ctypes.CDLL:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    return libc


def abi_version() -> int:
    """Return the kernel's Landlock ABI version, or 0 if unavailable."""
    if not sys.platform.startswith("linux"):
        return 0
    libc = _libc()
    result = libc.syscall(
        _NR_LANDLOCK_CREATE_RULESET, None, 0, _LANDLOCK_CREATE_RULESET_VERSION
    )
    return int(result) if result > 0 else 0


def landlock_supported() -> bool:
    """Return whether Landlock filesystem rules can be applied on this host."""
    return abi_version() >= 1


def handled_access_fs(abi: int) -> int:
    """Return the set of FS access rights to handle at Landlock ABI *abi*.

    Requesting a right the running kernel does not support makes
    ``landlock_create_ruleset`` fail, so the handled set is masked to the ABI.
    """
    handled = 0
    for name, bit in ACCESS_FS.items():
        if name == "REFER" and abi < 2:
            continue
        if name == "TRUNCATE" and abi < 3:
            continue
        if name == "IOCTL_DEV" and abi < 5:
            continue
        handled |= bit
    return handled


def _runtime_read_paths() -> list[str]:
    """Paths the interpreter must keep reading/executing to run guest code.

    Without these, a Landlock ruleset that handles ``READ_FILE``/``EXECUTE``
    would stop the guest from importing the standard library or loading shared
    objects, breaking the interpreter rather than the guest's intent.
    """
    candidates = [
        sys.base_prefix,
        sys.base_exec_prefix,
        sys.prefix,
        sys.exec_prefix,
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/lib",
        "/lib",
        "/lib64",
        "/etc",  # ld.so.cache, ssl certs, locale data
    ]
    candidates.extend(p for p in sys.path if p)
    seen: dict[str, None] = {}
    for path in candidates:
        if path and os.path.exists(path):
            seen.setdefault(os.path.realpath(path), None)
    return list(seen)


def _add_path_rule(
    libc: ctypes.CDLL, ruleset_fd: int, path: str, access: int, handled: int
) -> bool:
    allowed = access & handled
    if not allowed:
        return False
    try:
        parent_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        attr = _PathBeneathAttr(allowed_access=allowed, parent_fd=parent_fd)
        result = libc.syscall(
            _NR_LANDLOCK_ADD_RULE,
            ruleset_fd,
            _LANDLOCK_RULE_PATH_BENEATH,
            ctypes.byref(attr),
            0,
        )
    finally:
        os.close(parent_fd)
    return result == 0


def apply_landlock(
    read_paths: list[str] | None,
    write_paths: list[str] | None,
    *,
    require: bool = False,
) -> LandlockReport:
    """Restrict the current process's filesystem access to the policy paths.

    ``read_paths`` are granted read access, ``write_paths`` read+write, and the
    interpreter's runtime paths are granted read+execute so it can keep running.
    Everything else that the ruleset handles is denied.  On a kernel without
    Landlock this is a no-op unless ``require`` is set, in which case it raises.
    """
    report = LandlockReport()
    abi = abi_version()
    report.abi = abi
    if abi < 1:
        if require:
            raise RuntimeError("Landlock confinement required but unsupported")
        report.skipped = "unsupported"
        return report

    handled = handled_access_fs(abi)
    libc = _libc()
    attr = _RulesetAttr(handled_access_fs=handled)
    ruleset_fd = libc.syscall(
        _NR_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0
    )
    if ruleset_fd < 0:
        err = ctypes.get_errno()
        if require:
            raise OSError(err, "landlock_create_ruleset failed")
        report.skipped = f"create_ruleset_failed:{err}"
        return report

    try:
        for path in _runtime_read_paths():
            if _add_path_rule(libc, ruleset_fd, path, _READ_EXEC, handled):
                report.rules += 1
        for path in read_paths or []:
            if _add_path_rule(libc, ruleset_fd, path, _READ, handled):
                report.rules += 1
        for path in write_paths or []:
            if _add_path_rule(libc, ruleset_fd, path, _WRITE, handled):
                report.rules += 1

        # PR_SET_NO_NEW_PRIVS is set by apply_confinement before this runs, which
        # landlock_restrict_self requires when unprivileged.
        result = libc.syscall(_NR_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0)
        if result != 0:
            err = ctypes.get_errno()
            if require:
                raise OSError(err, "landlock_restrict_self failed")
            report.skipped = f"restrict_self_failed:{err}"
            return report
    finally:
        os.close(ruleset_fd)

    report.applied = True
    return report
