"""Landlock filesystem and TCP-egress confinement for ``backend="process"``.

Landlock lets an unprivileged process irrevocably restrict its own filesystem
access to an allow-list of path hierarchies, enforced by the kernel.  Applied to
a guest process (which already has ``PR_SET_NO_NEW_PRIVS`` set by
:mod:`pyisolate.runtime.confine`), it turns the sandbox's filesystem policy into
a real kernel boundary: even guest code that defeats the Python ``open`` guard
and reaches the libc ``open``/``openat`` can only touch permitted paths.

From Landlock ABI 4 (Linux 6.7) the same mechanism can allow-list the TCP ports
a process may ``connect()`` to. PyIsolate maps the policy's TCP allow-list onto
that layer so network egress is denied by the kernel to any port the policy did
not permit, even if guest code walks ``object.__subclasses__()`` to a raw
socket. Landlock's network rules are keyed on port, not address, so this is a
coarse kernel backstop beneath the userspace host:port guard, not a replacement
for it.

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
_LANDLOCK_RULE_NET_PORT = 2

# Landlock ABI that introduced TCP network rules (Linux 6.7). Below it the
# kernel has no notion of ``handled_access_net`` and network egress cannot be
# confined by Landlock.
_NET_ABI = 4

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

# TCP network access rights (ABI >= 4). Bit positions are a stable kernel ABI.
ACCESS_NET = {
    "BIND_TCP": 1 << 0,
    "CONNECT_TCP": 1 << 1,
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


class _RulesetAttrNet(ctypes.Structure):
    # ``struct landlock_ruleset_attr`` grew ``handled_access_net`` at ABI 4.
    # Passing a struct sized to include it is only valid on a kernel that knows
    # the field; on older kernels the fs-only :class:`_RulesetAttr` is used.
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _NetPortAttr(ctypes.Structure):
    # ``struct landlock_net_port_attr { __u64 allowed_access; __u64 port; }`` —
    # both members are naturally aligned u64s, so no packing is required.
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


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
    net_applied: bool = False
    net_rules: int = 0
    allowed_ports: list[int] = field(default_factory=list)
    net_skipped: str | None = None


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


def net_supported() -> bool:
    """Return whether Landlock TCP network rules can be applied on this host."""
    return abi_version() >= _NET_ABI


def handled_access_net(abi: int) -> int:
    """Return the set of TCP network rights to handle at Landlock ABI *abi*.

    Only ``CONNECT_TCP`` is handled: this layer confines outbound egress. TCP
    ``bind`` (listening) is out of scope for the network-egress boundary and is
    left to seccomp/policy. Returns 0 below the ABI that introduced net rules.
    """
    if abi < _NET_ABI:
        return 0
    return ACCESS_NET["CONNECT_TCP"]


def _parse_port(destination: str) -> int | None:
    """Extract the TCP port from a ``"host:port"`` allow-list destination.

    Returns ``None`` when the destination has no parseable ``:port`` suffix in
    the valid 1-65535 range (for example a bare hostname, or an unbracketed
    IPv6 literal). Landlock can only allow-list ports, so such a destination
    cannot be represented and the caller must decide how to degrade.
    """
    _, sep, tail = destination.rpartition(":")
    if not sep:
        return None
    try:
        port = int(tail)
    except ValueError:
        return None
    if 1 <= port <= 65535:
        return port
    return None


def connect_ports_from_destinations(
    destinations: list[str],
) -> tuple[list[int], bool]:
    """Turn a TCP allow-list into a de-duplicated set of connect ports.

    Returns ``(ports, exact)``. ``exact`` is ``False`` when any destination
    lacked a parseable port; a network Landlock ruleset is default-deny for
    every port it does not name, so an inexact allow-list would silently block a
    destination the policy actually permits. Callers should skip network
    Landlock in that case and rely on the userspace guard instead.
    """
    ports: list[int] = []
    seen: set[int] = set()
    exact = True
    for dest in destinations:
        port = _parse_port(dest)
        if port is None:
            exact = False
            continue
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return ports, exact


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


def _add_net_port_rule(
    libc: ctypes.CDLL, ruleset_fd: int, port: int, access: int
) -> bool:
    attr = _NetPortAttr(allowed_access=access, port=port)
    result = libc.syscall(
        _NR_LANDLOCK_ADD_RULE,
        ruleset_fd,
        _LANDLOCK_RULE_NET_PORT,
        ctypes.byref(attr),
        0,
    )
    return result == 0


def _populate_fs_rules(
    libc: ctypes.CDLL,
    ruleset_fd: int,
    read_paths: list[str] | None,
    write_paths: list[str] | None,
    handled_fs: int,
    report: LandlockReport,
) -> None:
    """Add the interpreter, read, and write path rules to *ruleset_fd*."""
    for path in _runtime_read_paths():
        if _add_path_rule(libc, ruleset_fd, path, _READ_EXEC, handled_fs):
            report.rules += 1
    for path in read_paths or []:
        if _add_path_rule(libc, ruleset_fd, path, _READ, handled_fs):
            report.rules += 1
    for path in write_paths or []:
        if _add_path_rule(libc, ruleset_fd, path, _WRITE, handled_fs):
            report.rules += 1


def _populate_net_rules(
    libc: ctypes.CDLL,
    ruleset_fd: int,
    connect_ports: list[int],
    report: LandlockReport,
) -> None:
    """Add a CONNECT_TCP allow rule for each policy port to *ruleset_fd*."""
    for port in connect_ports:
        if _add_net_port_rule(libc, ruleset_fd, port, ACCESS_NET["CONNECT_TCP"]):
            report.net_rules += 1
            report.allowed_ports.append(port)


def apply_landlock(
    read_paths: list[str] | None,
    write_paths: list[str] | None,
    *,
    connect_ports: list[int] | None = None,
    require: bool = False,
) -> LandlockReport:
    """Restrict the current process's filesystem and TCP-egress access to policy.

    ``read_paths`` are granted read access, ``write_paths`` read+write, and the
    interpreter's runtime paths are granted read+execute so it can keep running.
    ``connect_ports`` (Landlock ABI >= 4, Linux 6.7+) allow-lists the TCP ports
    the guest may ``connect()`` to; every other port is denied by the kernel.
    Both layers share a single ruleset. A layer whose allow-list is empty/None
    is not handled at all, so a default-deny ruleset never breaks the
    interpreter or blocks egress the policy did not mean to restrict.

    On a kernel without Landlock this is a no-op unless ``require`` is set, in
    which case it raises. When network confinement is requested but the kernel's
    Landlock ABI predates net rules, the filesystem layer is still applied and
    the network layer is recorded as skipped (or raises under ``require``).
    """
    report = LandlockReport()
    abi = abi_version()
    report.abi = abi
    if abi < 1:
        if require:
            raise RuntimeError("Landlock confinement required but unsupported")
        report.skipped = "unsupported"
        return report

    handle_fs = bool(read_paths or write_paths)
    want_net = connect_ports is not None
    handle_net = want_net and abi >= _NET_ABI
    if want_net and not handle_net:
        if require:
            raise RuntimeError(
                "Landlock network confinement required but unsupported "
                f"(ABI {abi} < {_NET_ABI})"
            )
        report.net_skipped = f"net_unsupported_abi:{abi}"

    if not handle_fs and not handle_net:
        # Nothing to restrict. A ruleset that handled an access class with no
        # allow-list rules would be default-deny and break the guest.
        report.skipped = "no_rules"
        return report

    handled_fs = handled_access_fs(abi) if handle_fs else 0
    handled_net = handled_access_net(abi) if handle_net else 0

    libc = _libc()
    if handled_net:
        attr: ctypes.Structure = _RulesetAttrNet(
            handled_access_fs=handled_fs, handled_access_net=handled_net
        )
    else:
        attr = _RulesetAttr(handled_access_fs=handled_fs)
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
        if handle_fs:
            _populate_fs_rules(
                libc, ruleset_fd, read_paths, write_paths, handled_fs, report
            )
        if handle_net:
            _populate_net_rules(libc, ruleset_fd, connect_ports or [], report)

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

    report.applied = handle_fs
    report.net_applied = handle_net
    return report
