"""Authoritative contract between the policy compiler and the eBPF LSM program.

The kernel program ``syscall_filter.bpf.c`` enforces policy by looking up
``sandbox_policy[bpf_get_current_cgroup_id()]`` and denying operations whose
capability-class bit is set in ``deny_mask``.  For that lookup to hit, userspace
must write the map with:

* **key** = the sandbox's cgroup id, which is the cgroup directory's inode
  number (what ``bpf_get_current_cgroup_id`` returns), as a little-endian u64;
* **value** = ``struct pyisolate_policy { __u32 deny_mask; __u32 audit_only; }``,
  little-endian.

This module is the single source of truth for those constants and their byte
encoding, shared by the manager (which writes the map) and the tests (which
assert the encoding matches the kernel struct).

Granularity note: ``deny_mask`` is a coarse per-cgroup, per-capability-class
switch.  It can express "deny all filesystem" or "deny all network", but not
"allow only ``/srv/data``".  Fine-grained filesystem access is enforced by
Landlock and fine-grained network by the broker; the eBPF mask handles the
always-denied classes (process creation, ptrace/mount/bpf) and whole-class
denial when the policy grants nothing in a class.
"""

from __future__ import annotations

import os

from ..policy.model import RuntimePolicy

# Capability-class deny bits. These MUST match the ``PYI_DENY_*`` defines in
# syscall_filter.bpf.c.
DENY_FS = 1 << 0
DENY_NET = 1 << 1
DENY_PROCESS = 1 << 2
DENY_RISKY = 1 << 3

#: Name of the pinned map the LSM program consults (defined in the .bpf.c).
SANDBOX_POLICY_MAP = "sandbox_policy"


def _policy_allows_any_fs(policy: object) -> bool:
    if policy is None:
        return False
    if isinstance(policy, RuntimePolicy):
        return bool(policy.allow_fs)
    if getattr(policy, "fs", None):
        return True
    for cap in getattr(policy, "capabilities", None) or []:
        if getattr(cap, "kind", None) in ("read_path", "write_path"):
            return True
    return False


def _policy_allows_any_net(policy: object) -> bool:
    if policy is None:
        return False
    if isinstance(policy, RuntimePolicy):
        return bool(policy.allow_tcp)
    if getattr(policy, "tcp", None):
        return True
    for cap in getattr(policy, "capabilities", None) or []:
        if getattr(cap, "kind", None) == "connect_tcp":
            return True
    return False


def compile_deny_mask(policy: object) -> int:
    """Derive the coarse per-cgroup ``deny_mask`` enforced by the LSM program.

    Process creation and risky operations (ptrace/mount/bpf) are always denied
    inside a sandbox cgroup -- the sandbox never execs and the broker performs
    privileged work from a different cgroup.  Filesystem and network are denied
    as whole classes only when the policy grants nothing in that class; anything
    finer is delegated to Landlock and the broker.
    """
    mask = DENY_PROCESS | DENY_RISKY
    if not _policy_allows_any_fs(policy):
        mask |= DENY_FS
    if not _policy_allows_any_net(policy):
        mask |= DENY_NET
    return mask


def _byte_tokens(data: bytes) -> list[str]:
    """Return ``["0x..", ...]`` tokens ``bpftool map update`` consumes."""
    return [f"0x{byte:02x}" for byte in data]


def encode_sandbox_policy_key(cgroup_id: int) -> list[str]:
    """Encode a cgroup id as the little-endian u64 map key."""
    return _byte_tokens(int(cgroup_id).to_bytes(8, "little"))


def encode_sandbox_policy_value(deny_mask: int, audit_only: bool = False) -> list[str]:
    """Encode ``struct pyisolate_policy`` (two little-endian u32s)."""
    return _byte_tokens(
        int(deny_mask).to_bytes(4, "little")
        + (1 if audit_only else 0).to_bytes(4, "little")
    )


def cgroup_id_for_path(path: "str | os.PathLike[str] | None") -> int | None:
    """Return the cgroup id (directory inode) for *path*, or ``None``.

    ``bpf_get_current_cgroup_id()`` returns the cgroupfs directory inode, so the
    inode is exactly the key the kernel program will look the policy up under.
    """
    if path is None:
        return None
    try:
        return os.stat(path).st_ino
    except OSError:
        return None
