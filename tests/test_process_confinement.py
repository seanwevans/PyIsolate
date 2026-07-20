"""Tests for kernel confinement of ``backend="process"`` guest processes.

The seccomp/rlimit layer is x86-64-Linux specific; tests that depend on the
filter actually being installed skip elsewhere. Tests that install a
kill-on-syscall filter run in a forked child so a denied syscall cannot take
down the pytest process.
"""

import os
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.runtime import confine

requires_seccomp = pytest.mark.skipif(
    not confine.seccomp_supported(),
    reason="seccomp deny-list filter is implemented for x86-64 Linux only",
)

# Escape that defeats the Python import guard and reaches the *real* os, then
# calls the real execve -- which the kernel seccomp filter must kill.
_ESCAPE_EXECVE = """
for cls in ().__class__.__base__.__subclasses__():
    if cls.__name__ == "catch_warnings":
        _os = cls()._module.__builtins__["__import__"]("os")
        post("reached-os")
        _os.execv("/bin/true", ["/bin/true"])
        break
"""


def test_filter_program_has_only_valid_forward_jumps():
    # Regression guard: an earlier builder double-counted the instruction index
    # and produced negative jump offsets that wrapped to 255 in the u8 field,
    # which the kernel rejects with EINVAL. Every jump must land inside the
    # program and every path must end in a RET.
    denied = list(confine.DANGEROUS_SYSCALLS_X86_64.values())
    program = confine._build_filter_program(denied)
    length = len(program)
    assert length == len(denied) + 6
    _BPF_CLASS_MASK = 0x07
    _BPF_JMP = 0x05
    _BPF_RET = 0x06
    for index in range(length):
        ins = program[index]
        if ins.code & _BPF_CLASS_MASK == _BPF_JMP:
            # Only jump instructions consult jt/jf; both targets must be in range.
            assert index + 1 + ins.jt < length, f"jt out of bounds at {index}"
            assert index + 1 + ins.jf < length, f"jf out of bounds at {index}"
    # Last two instructions are the ALLOW then KILL returns.
    assert program[length - 1].code & _BPF_CLASS_MASK == _BPF_RET
    assert program[length - 2].code & _BPF_CLASS_MASK == _BPF_RET


def _run_in_forked_child(fn) -> int:
    """Run ``fn`` in a forked child and return its exit status word."""
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        try:
            fn()
        except BaseException:
            os._exit(70)
        os._exit(0)
    _, status = os.waitpid(pid, 0)
    return status


@requires_seccomp
def test_apply_confinement_installs_seccomp_and_allows_normal_syscalls(tmp_path):
    marker = tmp_path / "ok.txt"

    def child():
        report = confine.apply_confinement()
        assert report.seccomp is True
        assert report.no_new_privs is True
        assert report.seccomp_denied == len(confine.DANGEROUS_SYSCALLS_X86_64)
        # Ordinary syscalls (open/write/read) must still work after the filter.
        marker.write_text("ok", encoding="utf-8")
        assert marker.read_text(encoding="utf-8") == "ok"

    status = _run_in_forked_child(child)
    assert os.WIFEXITED(status)
    assert os.WEXITSTATUS(status) == 0
    assert marker.read_text(encoding="utf-8") == "ok"


@requires_seccomp
def test_seccomp_kills_process_on_denied_syscall():
    def child():
        confine.apply_confinement()
        # execve is on the deny-list; this must be killed by SIGSYS, not run.
        os.execv("/bin/true", ["/bin/true"])

    status = _run_in_forked_child(child)
    assert os.WIFSIGNALED(status)
    assert os.WTERMSIG(status) == signal.SIGSYS


def test_apply_confinement_disables_core_dumps():
    def child():
        report = confine.apply_confinement(seccomp=False)
        assert "core=0" in report.rlimits

    status = _run_in_forked_child(child)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0


@requires_seccomp
def test_process_sandbox_is_confined_by_default():
    with iso.spawn("conf-default", allowed_imports=["math"], backend="process") as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert report is not None
        assert report["seccomp"] is True
        # Confinement does not break ordinary guest execution.
        sb.exec("from math import sqrt; post(sqrt(9))")
        assert sb.recv(timeout=5) == 3.0


@requires_seccomp
def test_real_execve_escape_is_killed_by_the_kernel():
    # The guest defeats the Python import guard and reaches the real os.execv;
    # the seccomp filter must kill the guest process at the kernel level.
    sb = iso.spawn("conf-escape", allowed_imports=["math"], backend="process")
    try:
        sb.exec(_ESCAPE_EXECVE)
        assert sb.recv(timeout=5) == "reached-os"
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)
        sb.close()
        # -SIGSYS confirms the kernel (not a normal exit) terminated the guest.
        assert sb._thread.returncode == -signal.SIGSYS
    finally:
        sb.close()


def test_process_sandbox_confinement_can_be_disabled():
    from pyisolate.runtime.process_backend import ProcessSandbox

    proc = ProcessSandbox("conf-off", allowed_imports=["math"], confine=False)
    try:
        proc.exec("from math import sqrt; post(sqrt(4))")
        assert proc.recv(timeout=5) == 2.0
        assert proc.confinement is None
    finally:
        proc.stop()
