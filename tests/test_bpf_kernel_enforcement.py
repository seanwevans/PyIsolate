import os
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from pyisolate.bpf.manager import BPFManager

ROOT = Path(__file__).resolve().parents[1]
SYSCALL_FILTER = ROOT / "pyisolate" / "bpf" / "syscall_filter.bpf.c"
RESOURCE_GUARD = ROOT / "pyisolate" / "bpf" / "resource_guard.bpf.c"


def test_syscall_filter_uses_lsm_hooks_and_cgroup_policy_maps():
    src = SYSCALL_FILTER.read_text()

    assert 'SEC("lsm/file_open")' in src
    assert 'SEC("lsm/socket_connect")' in src
    assert 'SEC("lsm/socket_create")' in src
    assert 'SEC("lsm/task_alloc")' in src
    assert 'SEC("lsm/bprm_check_security")' in src
    assert 'SEC("lsm/ptrace_access_check")' in src
    assert 'SEC("lsm/sb_mount")' in src
    assert 'SEC("lsm/bpf")' in src
    assert "bpf_get_current_cgroup_id" in src
    assert "sandbox_policy" in src
    assert "syscall_policy" in src
    assert "return -EPERM" in src


def test_resource_guard_uses_ringbuf_and_per_cgroup_accounting_maps():
    src = RESOURCE_GUARD.read_text()

    assert "BPF_MAP_TYPE_RINGBUF" in src
    assert "resource_events" in src
    assert "cgroup_accounting" in src
    assert "cgroup_quotas" in src
    assert 'SEC("tracepoint/sched/sched_switch")' in src
    assert 'SEC("tracepoint/exceptions/page_fault_user")' in src
    assert 'SEC("cgroup_skb/egress")' in src
    assert "emit_if_breached" in src


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
