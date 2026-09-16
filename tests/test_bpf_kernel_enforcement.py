"""Kernel-enforcement tests for the eBPF programs.

These used to assert that certain strings appeared in the ``.bpf.c`` sources,
which passes for a program the verifier would reject. The checks here compile
the real sources with the real command the manager uses and inspect the
resulting ELF, so the two defects that made these programs unloadable on every
kernel stay fixed:

* an object built without ``-g`` carries no BTF, and BTF-defined maps are
  described entirely by their BTF type, so libbpf cannot parse the ``.maps``
  section at all;
* an LSM program is called with one argument -- a pointer to the array of hook
  arguments -- so a handler declared with typed parameters reads ``r2``, which
  the caller never sets, and the verifier rejects it with ``R2 !read_ok``.

Loading and attaching still needs a kernel with BPF-LSM plus root and
``bpftool``; that remains the env-gated test at the bottom.
"""

import os
import re
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from pyisolate.bpf.manager import BPFManager

ROOT = Path(__file__).resolve().parents[1]
BPF_DIR = ROOT / "pyisolate" / "bpf"
SYSCALL_FILTER = BPF_DIR / "syscall_filter.bpf.c"
RESOURCE_GUARD = BPF_DIR / "resource_guard.bpf.c"

requires_clang = pytest.mark.skipif(
    shutil.which("clang") is None, reason="clang is required to compile BPF objects"
)
requires_objdump = pytest.mark.skipif(
    shutil.which("llvm-objdump") is None, reason="llvm-objdump is required"
)

#: Every LSM hook the filter installs, and the program section it lives in.
LSM_SECTIONS = (
    "lsm/file_open",
    "lsm/file_truncate",
    "lsm/socket_create",
    "lsm/socket_connect",
    "lsm/task_alloc",
    "lsm/bprm_check_security",
    "lsm/ptrace_access_check",
    "lsm/sb_mount",
    "lsm/bpf",
)


def _compile(source: Path, tmp_path: Path) -> Path:
    """Build *source* with the manager's own command and return the object."""
    obj = tmp_path / (source.stem + ".o")
    subprocess.run(
        BPFManager._compile_command(source, obj), check=True, capture_output=True
    )
    return obj


def _sections(obj: Path) -> list[str]:
    out = subprocess.run(
        ["llvm-objdump", "-h", str(obj)], check=True, capture_output=True, text=True
    ).stdout
    return re.findall(r"^\s*\d+\s+(\S+)", out, re.MULTILINE)


# --- the compile command itself -------------------------------------------


def test_compile_command_requests_btf():
    """Without -g there is no BTF, and without BTF nothing loads."""
    assert "-g" in BPFManager.COMPILE_FLAGS
    cmd = BPFManager._compile_command(Path("in.bpf.c"), Path("out.o"))
    assert cmd[0] == "clang"
    assert "-g" in cmd
    assert cmd[-4:] == ["-c", "in.bpf.c", "-o", "out.o"]


@requires_clang
@requires_objdump
@pytest.mark.parametrize("source", [SYSCALL_FILTER, RESOURCE_GUARD])
def test_compiled_objects_carry_btf(source, tmp_path):
    sections = _sections(_compile(source, tmp_path))
    assert ".BTF" in sections, f"{source.name} has no BTF; libbpf cannot load it"
    assert ".BTF.ext" in sections


@requires_clang
@requires_objdump
def test_filter_emits_every_lsm_hook_as_its_own_program(tmp_path):
    sections = _sections(_compile(SYSCALL_FILTER, tmp_path))
    for section in LSM_SECTIONS:
        assert section in sections, f"missing program section {section}"


# --- the calling convention -----------------------------------------------


def _disassemble(obj: Path, section: str | None = None) -> list[str]:
    """Return the instruction text of *obj*, optionally for one section."""
    cmd = ["llvm-objdump", "-d", str(obj)]
    if section is not None:
        cmd.insert(2, f"--section={section}")
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    instructions = []
    for line in out.splitlines():
        if not re.match(r"^\s+[0-9a-f]+:", line):
            continue
        # "   0:\t79 10 08 ...\tr0 = *(u64 *)(r1 + 0x8)" -- text is the last field.
        fields = line.split("\t")
        if len(fields) >= 3:
            instructions.append(fields[-1].strip())
    return instructions


@requires_clang
@requires_objdump
@pytest.mark.parametrize("section", LSM_SECTIONS)
def test_lsm_programs_read_arguments_from_the_context_pointer(section, tmp_path):
    """Hook arguments must come from the ctx array, not from r2.

    A BPF LSM program is invoked with a single argument in ``r1``: the pointer
    to the hook's argument array. Reading ``r2`` reads an uninitialised
    register and the verifier refuses the program, so the first thing each
    handler does has to be a load through ``r1``.
    """
    instructions = _disassemble(_compile(SYSCALL_FILTER, tmp_path), section)
    assert instructions, f"no instructions disassembled for {section}"
    first = instructions[0]
    assert re.fullmatch(r"r\d+ = \*\(u64 \*\)\(r1 \+ 0x[0-9a-f]+\)", first), (
        f"{section} starts with {first!r}; an LSM program must begin by loading "
        "its arguments out of the context array in r1"
    )


@requires_clang
@requires_objdump
@pytest.mark.parametrize("source", [SYSCALL_FILTER, RESOURCE_GUARD])
def test_no_program_entry_reads_an_uninitialised_argument_register(source, tmp_path):
    """The signature of the typed-parameter form this replaced.

    Declaring ``int handler(void *file, int ret)`` compiles to ``r0 = r2`` at
    entry. A BPF program is entered with only ``r1`` set, so a move out of
    ``r2``..``r5`` as the first instruction is reading nothing.

    Only entry points are checked. Inside ``.text`` the same move is an
    ordinary argument register for a real call, which is why a whole-object
    scan would flag correct code.
    """
    obj = _compile(source, tmp_path)
    programs = [s for s in _sections(obj) if "/" in s]
    assert programs, f"{source.name} defines no program sections"
    for section in programs:
        instructions = _disassemble(obj, section)
        assert instructions, f"no instructions in {section}"
        assert not re.fullmatch(r"r\d+ = r[2-5]", instructions[0]), (
            f"{source.name}:{section} enters with {instructions[0]!r}, which "
            "reads a register the caller never set"
        )


def test_lsm_handlers_take_the_context_array(tmp_path):
    """Source-level guard against regressing to typed parameters."""
    src = SYSCALL_FILTER.read_text(encoding="utf-8")
    handlers = re.findall(
        r'SEC\("lsm/[a-z_]+"\)\s*\n\s*int\s+(\w+)\(([^)]*)\)', src, re.MULTILINE
    )
    assert len(handlers) == len(LSM_SECTIONS)
    for name, params in handlers:
        assert params.strip() == "__u64 *ctx", (
            f"{name} declares {params!r}; an LSM program receives only the "
            "context array, so typed parameters read registers the caller "
            "never set"
        )


def test_socket_connect_copies_the_sockaddr_instead_of_dereferencing_it():
    """A kernel pointer that is not BTF-typed cannot be loaded through."""
    src = SYSCALL_FILTER.read_text(encoding="utf-8")
    assert "bpf_probe_read_kernel" in src
    assert "address->sa_family" not in src


# --- map definitions ------------------------------------------------------


def test_resource_guard_defines_only_real_maps():
    """`struct { int dummy; }` is not a map definition libbpf can parse.

    A BTF-defined map is described entirely by its BTF type. A placeholder
    struct in the ``.maps`` section makes libbpf reject the whole object, so
    the guard must not carry any.
    """
    src = RESOURCE_GUARD.read_text(encoding="utf-8")
    maps = re.findall(r"struct \{(.*?)\}\s*(\w+) SEC\(\"\.maps\"\)", src, re.DOTALL)
    assert maps, "resource guard defines no maps"
    for body, name in maps:
        assert "__uint(type," in body, f"map {name} has no BPF_MAP_TYPE_*"
        assert "int dummy" not in body, f"map {name} is a placeholder, not a map"
    names = {name for _, name in maps}
    assert {"resource_events", "cgroup_accounting", "cgroup_quotas"} <= names


def test_resource_guard_has_no_dead_placeholder_programs():
    src = RESOURCE_GUARD.read_text(encoding="utf-8")
    assert "emit_breach" not in src
    assert "Real implementation" not in src


def test_syscall_filter_keys_every_decision_on_the_cgroup():
    src = SYSCALL_FILTER.read_text(encoding="utf-8")
    assert "bpf_get_current_cgroup_id" in src
    assert "sandbox_policy" in src
    assert "syscall_policy" in src
    assert "return -EPERM" in src


# --- loader wiring --------------------------------------------------------


def test_manager_loads_and_attaches_kernel_programs(monkeypatch):
    calls = []

    def record(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr = BPFManager()

    mgr.load(mode="hardened")

    assert any(
        cmd[:3] == ["bpftool", "prog", "loadall"] and "autoattach" in cmd
        for cmd in calls
    )
    assert any(cmd[:3] == ["bpftool", "cgroup", "attach"] for cmd in calls)
    assert mgr.loaded is True
    # Every clang invocation must ask for BTF, or the loadall above fails.
    compiles = [cmd for cmd in calls if cmd and cmd[0] == "clang"]
    assert compiles, "no programs were compiled"
    for cmd in compiles:
        assert "-g" in cmd, f"compile without BTF: {cmd}"


# --- live kernel ----------------------------------------------------------


@pytest.mark.skipif(
    os.environ.get("PYISOLATE_LIVE_BPF_TESTS") != "1"
    or os.geteuid() != 0
    or shutil.which("bpftool") is None,
    reason="live kernel-enforcement test requires root, bpftool, and PYISOLATE_LIVE_BPF_TESTS=1",
)
def test_live_kernel_policy_blocks_unwrapped_file_network_and_process_actions(tmp_path):
    """Exercise kernel policy directly; no PyIsolate Python wrappers are used."""

    mgr = BPFManager()
    mgr.load(mode="hardened")

    cgroup_id = os.stat("/sys/fs/cgroup").st_ino
    key = cgroup_id.to_bytes(8, "little")
    value = (15).to_bytes(4, "little") + (0).to_bytes(4, "little")
    policy_map = "/sys/fs/bpf/pyisolate/sandbox_policy"
    subprocess.run(
        [
            "bpftool",
            "map",
            "update",
            "pinned",
            policy_map,
            "key",
            "hex",
            *[f"{byte:02x}" for byte in key],
            "value",
            "hex",
            *[f"{byte:02x}" for byte in value],
            "any",
        ],
        check=True,
    )

    with pytest.raises(PermissionError):
        (tmp_path / "blocked.txt").write_text("blocked by LSM")

    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", 9), timeout=0.05)

    with pytest.raises(PermissionError):
        subprocess.run(["/bin/true"], check=True)


@pytest.mark.skipif(
    os.environ.get("PYISOLATE_LIVE_BPF_TESTS") != "1"
    or os.geteuid() != 0
    or shutil.which("bpftool") is None,
    reason="verifier test requires root, bpftool, and PYISOLATE_LIVE_BPF_TESTS=1",
)
def test_verifier_accepts_the_filter_programs(tmp_path):
    """The narrow check: does the kernel verifier accept what clang produced?

    Separate from the enforcement test above so a verifier rejection is
    reported as a compile/codegen defect rather than as a policy failure.
    """
    obj = _compile(SYSCALL_FILTER, tmp_path)
    result = subprocess.run(
        [
            "bpftool",
            "prog",
            "loadall",
            str(obj),
            str(tmp_path / "pinned"),
            "type",
            "lsm",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"verifier rejected the filter:\n{result.stderr}"
