"""Tests for the userspace<->eBPF policy-map contract.

The kernel LSM program enforces policy via ``sandbox_policy[cgroup_id]``. These
tests verify that userspace derives the right deny-mask, encodes the map key and
value exactly as the kernel struct expects, and -- crucially -- writes the map
the kernel program actually defines. The last point is a guard against the
class of bug where userspace programs a map name the kernel never reads.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
import pyisolate.bpf.manager as manager
from pyisolate.bpf import contract

_BPF_SRC = ROOT / "pyisolate" / "bpf" / "syscall_filter.bpf.c"


def _kernel_map_names() -> set[str]:
    text = _BPF_SRC.read_text(encoding="utf-8")
    return set(re.findall(r"\}\s*([A-Za-z_]\w*)\s*SEC\(\"\.maps\"\)", text))


def _kernel_deny_defines() -> dict[str, int]:
    text = _BPF_SRC.read_text(encoding="utf-8")
    found = {}
    for name, shift in re.findall(r"#define\s+(PYI_DENY_\w+)\s+\(1U\s*<<\s*(\d+)\)", text):
        found[name] = 1 << int(shift)
    return found


def test_enforcement_map_is_defined_in_the_kernel_program():
    # The map userspace writes for enforcement must be one the LSM program reads.
    assert contract.SANDBOX_POLICY_MAP in _kernel_map_names()


def test_deny_mask_bits_match_kernel_defines():
    # Guard against the Python constants drifting from the .bpf.c #defines.
    kernel = _kernel_deny_defines()
    assert kernel["PYI_DENY_FS"] == contract.DENY_FS
    assert kernel["PYI_DENY_NET"] == contract.DENY_NET
    assert kernel["PYI_DENY_PROCESS"] == contract.DENY_PROCESS
    assert kernel["PYI_DENY_RISKY"] == contract.DENY_RISKY


def test_compile_deny_mask_denies_everything_without_a_policy():
    mask = contract.compile_deny_mask(None)
    assert mask == (
        contract.DENY_FS | contract.DENY_NET | contract.DENY_PROCESS | contract.DENY_RISKY
    )


def test_compile_deny_mask_always_denies_process_and_risky():
    for policy in (None, iso.policy.Policy().allow_fs("/tmp").allow_tcp("127.0.0.1:80")):
        mask = contract.compile_deny_mask(policy)
        assert mask & contract.DENY_PROCESS
        assert mask & contract.DENY_RISKY


def test_compile_deny_mask_clears_class_bits_when_granted():
    fs_only = contract.compile_deny_mask(iso.policy.Policy().allow_fs("/tmp"))
    assert not fs_only & contract.DENY_FS
    assert fs_only & contract.DENY_NET  # nothing granted for net

    net_only = contract.compile_deny_mask(iso.policy.Policy().allow_tcp("10.0.0.1:443"))
    assert not net_only & contract.DENY_NET
    assert net_only & contract.DENY_FS


def test_sandbox_policy_key_is_little_endian_u64():
    tokens = contract.encode_sandbox_policy_key(0x1122334455667788)
    raw = bytes(int(t, 16) for t in tokens)
    assert len(raw) == 8
    assert int.from_bytes(raw, "little") == 0x1122334455667788


def test_sandbox_policy_value_encodes_two_little_endian_u32():
    tokens = contract.encode_sandbox_policy_value(0xF, audit_only=True)
    raw = bytes(int(t, 16) for t in tokens)
    assert len(raw) == 8
    assert int.from_bytes(raw[:4], "little") == 0xF
    assert int.from_bytes(raw[4:], "little") == 1


def test_cgroup_id_for_path_returns_directory_inode(tmp_path):
    assert contract.cgroup_id_for_path(tmp_path) == tmp_path.stat().st_ino
    assert contract.cgroup_id_for_path(tmp_path / "missing") is None
    assert contract.cgroup_id_for_path(None) is None


def test_set_sandbox_policy_targets_the_pinned_map(monkeypatch):
    mgr = manager.BPFManager()
    captured = {}

    def fake_run(cmd, *, raise_on_error=False):
        captured["cmd"] = cmd
        return True

    monkeypatch.setattr(mgr, "_run", fake_run)
    assert mgr.set_sandbox_policy(11, contract.DENY_FS | contract.DENY_NET) is True

    cmd = captured["cmd"]
    assert cmd[:4] == ["bpftool", "map", "update", "pinned"]
    assert cmd[4].endswith("/pyisolate/sandbox_policy")
    key_tokens = cmd[cmd.index("key") + 1 : cmd.index("value")]
    assert bytes(int(t, 16) for t in key_tokens) == (11).to_bytes(8, "little")


def test_spawn_programs_the_sandbox_policy_map(monkeypatch):
    calls = []

    def fake_set(self, cgroup_id, deny_mask, **kwargs):
        calls.append((cgroup_id, deny_mask))
        return True

    monkeypatch.setattr(manager.BPFManager, "set_sandbox_policy", fake_set)

    sup = iso.Supervisor()
    try:
        sb = sup.spawn("kpol", allowed_imports=["math"])
        assert len(calls) == 1
        cgroup_id, deny_mask = calls[0]
        assert isinstance(cgroup_id, int) and cgroup_id > 0
        # No fs/net granted -> every class denied.
        assert deny_mask == (
            contract.DENY_FS
            | contract.DENY_NET
            | contract.DENY_PROCESS
            | contract.DENY_RISKY
        )
        sb.close()
    finally:
        sup.shutdown()
