"""Kernel-level confinement applied to a ``backend="process"`` guest process.

The process boundary (see :mod:`pyisolate.runtime.process_backend`) already
stops guest code from reaching the supervisor's address space.  This module
adds the *kernel* half of the boundary, applied inside the guest process before
any guest code runs:

* ``PR_SET_NO_NEW_PRIVS`` so the guest can never gain privileges (and so an
  unprivileged process is allowed to install a seccomp filter);
* a **seccomp** syscall filter that kills the process if it issues an
  unambiguously dangerous syscall -- executing new programs, tracing, mounting,
  joining/creating namespaces, loading kernel modules or BPF, reading another
  process's memory, and so on.  Because ``no_new_privs`` is set the filter
  cannot be removed, and seccomp filters are inherited across ``fork``/``clone``,
  so any child the guest spawns stays confined;
* resource limits (:mod:`resource`) that bound core dumps, address space, and
  CPU time.

This is a **deny-list**, not a complete allow-list: it is a strong, robust
reduction of the syscall attack surface that still lets a normal CPython
interpreter run, not a proof that only a fixed syscall set is reachable.  The
filter is x86-64 specific; on other architectures seccomp is skipped and the
report records that it was not applied.
"""

from __future__ import annotations

import ctypes
import platform
import resource
import sys
from dataclasses import dataclass, field

from . import landlock as _landlock

# prctl options
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

# seccomp return actions
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000

# BPF opcodes for the classic filter program seccomp consumes.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_RET = 0x06
_BPF_K = 0x00

# Audit arch token; the filter refuses to run under a different arch so a 32-bit
# or x32 syscall ABI cannot be used to reach a denied syscall by a different
# number.
_AUDIT_ARCH_X86_64 = 0xC000003E

# Offsets into ``struct seccomp_data``.
_SECCOMP_DATA_NR_OFFSET = 0
_SECCOMP_DATA_ARCH_OFFSET = 4

# x86-64 syscall numbers for the deny-list. These are a stable ABI and never
# change for this architecture. A normal compute workload never issues any of
# them; every entry is an escape, execution, kernel-management, or
# cross-process-memory primitive.
DANGEROUS_SYSCALLS_X86_64: dict[str, int] = {
    "execve": 59,
    "execveat": 322,
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "chroot": 161,
    "setns": 308,
    "unshare": 272,
    "kexec_load": 246,
    "kexec_file_load": 320,
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
    "bpf": 321,
    "perf_event_open": 298,
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "add_key": 248,
    "request_key": 249,
    "keyctl": 250,
    "reboot": 169,
    "swapon": 167,
    "swapoff": 168,
}


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


@dataclass
class ConfinementReport:
    """What confinement was actually applied to the guest process."""

    no_new_privs: bool = False
    seccomp: bool = False
    seccomp_denied: int = 0
    rlimits: list[str] = field(default_factory=list)
    landlock: bool = False
    landlock_rules: int = 0
    landlock_net: bool = False
    landlock_net_ports: int = 0
    skipped: list[str] = field(default_factory=list)


def _set_no_new_privs() -> bool:
    """Set ``PR_SET_NO_NEW_PRIVS`` on the current process. Returns success.

    Required both to install a seccomp filter and to call
    ``landlock_restrict_self`` while unprivileged.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0


def seccomp_supported() -> bool:
    """Return whether the seccomp filter in this module can be installed here."""
    return sys.platform.startswith("linux") and platform.machine() == "x86_64"


def _build_filter_program(denied: list[int]) -> "ctypes.Array[_SockFilter]":
    instructions: list[_SockFilter] = [
        # A = seccomp_data.arch
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _SECCOMP_DATA_ARCH_OFFSET),
        # if arch == x86-64, skip the kill; otherwise fall through to it
        _SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, 1, 0, _AUDIT_ARCH_X86_64),
        _SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        # A = seccomp_data.nr
        _SockFilter(_BPF_LD | _BPF_W | _BPF_ABS, 0, 0, _SECCOMP_DATA_NR_OFFSET),
    ]
    # One JEQ per denied syscall, each jumping to the shared KILL return that
    # sits immediately after the ALLOW return at the end of the program.
    count = len(denied)
    kill_index = len(instructions) + count + 1
    for nr in denied:
        # ``len(instructions)`` is the index this JEQ will occupy; on a match it
        # jumps forward to the shared KILL return at the end of the program.
        current_index = len(instructions)
        jt = kill_index - current_index - 1
        instructions.append(_SockFilter(_BPF_JMP | _BPF_JEQ | _BPF_K, jt, 0, nr))
    instructions.append(_SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_ALLOW))
    instructions.append(_SockFilter(_BPF_RET | _BPF_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))
    return (_SockFilter * len(instructions))(*instructions)


def install_seccomp_filter(denied: list[int] | None = None) -> int:
    """Install the seccomp deny-list filter. Returns the number of denied calls.

    Raises :class:`OSError` if ``no_new_privs`` or the filter cannot be set, and
    :class:`RuntimeError` on an unsupported architecture.
    """
    if not seccomp_supported():
        raise RuntimeError("seccomp filter is only implemented for x86-64 Linux")
    if denied is None:
        denied = list(DANGEROUS_SYSCALLS_X86_64.values())

    libc = ctypes.CDLL(None, use_errno=True)

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS) failed")

    program = _build_filter_program(denied)
    fprog = _SockFprog(len(program), program)
    if (
        libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0)
        != 0
    ):
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_SECCOMP) failed")
    return len(denied)


def _apply_rlimits(
    report: ConfinementReport,
    *,
    mem_bytes: int | None,
    cpu_seconds: int | None,
) -> None:
    # Never leak memory contents through a core dump of the guest.
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        report.rlimits.append("core=0")
    except (ValueError, OSError):
        report.skipped.append("rlimit_core")

    if mem_bytes is not None:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
            report.rlimits.append(f"as={mem_bytes}")
        except (ValueError, OSError):
            report.skipped.append("rlimit_as")

    if cpu_seconds is not None:
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            report.rlimits.append(f"cpu={cpu_seconds}")
        except (ValueError, OSError):
            report.skipped.append("rlimit_cpu")


def _apply_landlock(
    report: ConfinementReport,
    *,
    fs_read: list[str] | None,
    fs_write: list[str] | None,
    net_connect_ports: list[int] | None,
    require_landlock: bool,
) -> None:
    # Only handle an access class when the policy actually names an allow-list;
    # without one a default-deny ruleset would break the interpreter (FS) or
    # sever egress the policy meant to permit (network).
    if not fs_read and not fs_write and not net_connect_ports:
        return
    landlock_report = _landlock.apply_landlock(
        fs_read,
        fs_write,
        connect_ports=net_connect_ports,
        require=require_landlock,
    )
    if landlock_report.applied:
        report.landlock = True
        report.landlock_rules = landlock_report.rules
    elif fs_read or fs_write:
        report.skipped.append(f"landlock:{landlock_report.skipped}")
    if landlock_report.net_applied:
        report.landlock_net = True
        report.landlock_net_ports = landlock_report.net_rules
    elif net_connect_ports:
        reason = landlock_report.net_skipped or landlock_report.skipped
        report.skipped.append(f"landlock_net:{reason}")


def apply_confinement(
    *,
    mem_bytes: int | None = None,
    cpu_seconds: int | None = None,
    fs_read: list[str] | None = None,
    fs_write: list[str] | None = None,
    net_connect_ports: list[int] | None = None,
    seccomp: bool = True,
    require_seccomp: bool = False,
    require_landlock: bool = False,
) -> ConfinementReport:
    """Confine the *current* process before it runs guest code.

    Order matters: ``no_new_privs`` is set first (required by both Landlock and
    seccomp), then resource limits, then the Landlock filesystem/TCP-egress
    ruleset, and finally the seccomp filter as the last lockdown step. ``require_*`` turns an
    unsupported platform or a failed install into a raised error instead of a
    best-effort skip recorded in the report.
    """
    report = ConfinementReport()
    report.no_new_privs = _set_no_new_privs()

    _apply_rlimits(report, mem_bytes=mem_bytes, cpu_seconds=cpu_seconds)
    _apply_landlock(
        report,
        fs_read=fs_read,
        fs_write=fs_write,
        net_connect_ports=net_connect_ports,
        require_landlock=require_landlock,
    )

    if not seccomp:
        report.skipped.append("seccomp_disabled")
        return report

    if not seccomp_supported():
        if require_seccomp:
            raise RuntimeError(
                "seccomp confinement required but unsupported on this platform"
            )
        report.skipped.append("seccomp_unsupported")
        return report

    try:
        denied = install_seccomp_filter()
    except OSError as exc:
        if require_seccomp:
            raise
        report.skipped.append(f"seccomp_failed:{exc}")
        return report

    report.no_new_privs = True
    report.seccomp = True
    report.seccomp_denied = denied
    return report
