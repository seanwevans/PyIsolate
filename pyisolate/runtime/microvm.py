"""microVM backend scaffolding for ``backend="microvm"``.

This module is the supervisor-side groundwork for the microVM isolation mode:
the strongest boundary PyIsolate targets, where the guest runs behind a
hardware-virtualization boundary (KVM) instead of only kernel policy on a shared
kernel. It provides three things that do **not** require a running hypervisor to
be useful or testable:

* **capability detection** — is a supported VMM (Firecracker, Cloud Hypervisor,
  QEMU) on ``PATH`` and is ``/dev/kvm`` usable (:func:`detect_microvm_support`);
* **machine-config generation** — turn a sandbox's limits into the JSON a VMM
  consumes to boot a guest (:class:`MicroVMConfig`);
* **fail-closed admission** — a precise, actionable error when the host cannot
  provide the boundary (:func:`require_microvm_support`).

What it deliberately does **not** yet do is boot a guest or carry the cell
protocol over vsock; that launcher is the next increment. Until then the
supervisor routes ``backend="microvm"`` here and fails closed rather than
silently downgrading to a weaker boundary — consistent with the threat model,
which treats microVM as reserved and fail-closed.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Optional

from ..errors import SandboxError

# VMMs PyIsolate knows how to target, in preference order. The value is the
# executable name looked up on PATH.
_KNOWN_VMMS: tuple[tuple[str, str], ...] = (
    ("firecracker", "firecracker"),
    ("cloud-hypervisor", "cloud-hypervisor"),
    ("qemu", "qemu-system-x86_64"),
)

_KVM_DEVICE = "/dev/kvm"

# Default guest kernel command line for a Firecracker-style minimal boot.
_DEFAULT_BOOT_ARGS = "console=ttyS0 reboot=k panic=1 pci=off"


class MicroVMUnavailable(SandboxError):
    """Raised when a microVM boundary cannot be established on this host."""


@dataclass(frozen=True)
class MicroVMSupport:
    """Result of probing the host for microVM prerequisites."""

    vmm_kind: Optional[str]
    vmm_path: Optional[str]
    kvm: bool
    reasons: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        """Whether a hardware-VM boundary can be launched here."""
        return self.vmm_path is not None and self.kvm

    def as_dict(self) -> dict[str, Any]:
        return {
            "ready": self.ready,
            "vmm_kind": self.vmm_kind,
            "vmm_path": self.vmm_path,
            "kvm": self.kvm,
            "reasons": list(self.reasons),
        }


def detect_vmm() -> tuple[Optional[str], Optional[str]]:
    """Return the first supported VMM found on ``PATH`` as ``(kind, path)``."""
    for kind, executable in _KNOWN_VMMS:
        path = shutil.which(executable)
        if path is not None:
            return kind, path
    return None, None


def kvm_available() -> bool:
    """Return whether ``/dev/kvm`` exists and is readable+writable to us.

    KVM requires read/write access to the device node; a present-but-inaccessible
    ``/dev/kvm`` (missing group membership, container without the device) cannot
    launch a VM, so it is reported as unavailable.
    """
    return os.path.exists(_KVM_DEVICE) and os.access(_KVM_DEVICE, os.R_OK | os.W_OK)


def detect_microvm_support() -> MicroVMSupport:
    """Probe the host for a usable VMM and KVM, collecting the blocking reasons."""
    vmm_kind, vmm_path = detect_vmm()
    kvm = kvm_available()
    reasons: list[str] = []
    if vmm_path is None:
        names = ", ".join(executable for _, executable in _KNOWN_VMMS)
        reasons.append(f"no supported VMM on PATH (looked for: {names})")
    if not kvm:
        if not os.path.exists(_KVM_DEVICE):
            reasons.append(f"{_KVM_DEVICE} is not present (no hardware virtualization)")
        else:
            reasons.append(f"{_KVM_DEVICE} exists but is not readable+writable")
    return MicroVMSupport(
        vmm_kind=vmm_kind,
        vmm_path=vmm_path,
        kvm=kvm,
        reasons=tuple(reasons),
    )


def require_microvm_support(
    support: Optional[MicroVMSupport] = None,
) -> MicroVMSupport:
    """Return *support* if a microVM boundary is possible, else fail closed.

    The microVM backend has no weaker mode to degrade to: either a hardware-VM
    boundary can be launched or the request is refused. The raised error names
    every missing prerequisite so an operator can fix the host.
    """
    support = support or detect_microvm_support()
    if not support.ready:
        detail = "; ".join(support.reasons) or "prerequisites unavailable"
        raise MicroVMUnavailable(
            "backend='microvm' requires a hardware-VM boundary that this host "
            f"cannot provide: {detail}. Run on a host with a supported VMM and "
            "an accessible /dev/kvm, or choose backend='process' for kernel-level "
            "confinement without a VM."
        )
    return support


@dataclass
class MicroVMConfig:
    """Inputs for a guest microVM, renderable to a VMM machine configuration.

    The fields map onto a Firecracker-style boot: a guest kernel, a root
    filesystem image, CPU/memory sizing, and a vsock device used to carry the
    cell protocol between supervisor and guest.
    """

    kernel_image: str
    rootfs_image: str
    vsock_uds_path: str
    vcpus: int = 1
    mem_size_mib: int = 128
    guest_cid: int = 3
    boot_args: str = _DEFAULT_BOOT_ARGS
    rootfs_read_only: bool = False
    extra_drives: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.vcpus < 1:
            raise ValueError("vcpus must be >= 1")
        if self.mem_size_mib < 1:
            raise ValueError("mem_size_mib must be >= 1")
        # Firecracker reserves CIDs 0-2 (hypervisor/local/host); guests start at 3.
        if self.guest_cid < 3:
            raise ValueError("guest_cid must be >= 3 (0-2 are reserved)")

    @classmethod
    def from_limits(
        cls,
        *,
        kernel_image: str,
        rootfs_image: str,
        vsock_uds_path: str,
        mem_bytes: Optional[int] = None,
        vcpus: int = 1,
        guest_cid: int = 3,
    ) -> "MicroVMConfig":
        """Build a config from a sandbox's byte-denominated memory limit."""
        mem_mib = 128 if mem_bytes is None else max(1, math.ceil(mem_bytes / (1 << 20)))
        return cls(
            kernel_image=kernel_image,
            rootfs_image=rootfs_image,
            vsock_uds_path=vsock_uds_path,
            vcpus=vcpus,
            mem_size_mib=mem_mib,
            guest_cid=guest_cid,
        )

    def to_firecracker_json(self) -> dict[str, Any]:
        """Render the full-VM JSON Firecracker accepts via ``--config-file``."""
        drives = [
            {
                "drive_id": "rootfs",
                "path_on_host": self.rootfs_image,
                "is_root_device": True,
                "is_read_only": self.rootfs_read_only,
            }
        ]
        drives.extend(self.extra_drives)
        return {
            "boot-source": {
                "kernel_image_path": self.kernel_image,
                "boot_args": self.boot_args,
            },
            "drives": drives,
            "machine-config": {
                "vcpu_count": self.vcpus,
                "mem_size_mib": self.mem_size_mib,
                "smt": False,
            },
            "vsock": {
                "guest_cid": self.guest_cid,
                "uds_path": self.vsock_uds_path,
            },
        }


@dataclass
class LaunchedMicroVM:
    """A running VMM process and the on-disk artifacts backing it."""

    process: "subprocess.Popen[bytes]"
    workdir: str
    config_path: str
    api_socket: str
    vsock_uds_path: str

    @property
    def pid(self) -> int:
        return self.process.pid

    def is_alive(self) -> bool:
        return self.process.poll() is None


class MicroVMLauncher:
    """Materialize a guest config and manage the VMM process lifecycle.

    This is the mechanical layer beneath a running microVM: it writes the
    machine configuration to a per-VM working directory, builds the VMM command
    line, spawns the process, and tears it down. It does **not** yet complete the
    guest handshake -- the in-guest agent and the vsock cell transport are the
    next increment -- so a launched VM has no cell channel and the supervisor
    still refuses to hand back a usable sandbox.

    Only Firecracker's command line is implemented; a ready host running another
    supported VMM is reported as unimplemented rather than mis-launched.
    """

    def __init__(self, support: MicroVMSupport) -> None:
        self._support = support

    def build_command(self, config_path: str, api_socket: str) -> list[str]:
        """Return the argv that boots *config_path* on the detected VMM."""
        if self._support.vmm_path is None:
            raise MicroVMUnavailable("no VMM available to launch")
        if self._support.vmm_kind != "firecracker":
            raise MicroVMUnavailable(
                f"launching {self._support.vmm_kind!r} is not implemented yet; "
                "only Firecracker is wired up"
            )
        return [
            self._support.vmm_path,
            "--api-sock",
            api_socket,
            "--config-file",
            config_path,
        ]

    def _materialize_config(self, config: MicroVMConfig, workdir: str) -> str:
        config_path = os.path.join(workdir, "vm-config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config.to_firecracker_json(), handle, indent=2, sort_keys=True)
        return config_path

    def launch(
        self, config: MicroVMConfig, *, workdir: Optional[str] = None
    ) -> LaunchedMicroVM:
        """Write the config and start the VMM, returning a handle to it.

        The caller owns the returned VM and must call :meth:`terminate` to stop
        the process and remove the working directory.
        """
        owns_workdir = workdir is None
        workdir = workdir or tempfile.mkdtemp(prefix="pyisolate-vm-")
        try:
            config_path = self._materialize_config(config, workdir)
            api_socket = os.path.join(workdir, "firecracker.socket")
            command = self.build_command(config_path, api_socket)
            process: "subprocess.Popen[bytes]" = subprocess.Popen(
                command, close_fds=True
            )
        except BaseException:
            if owns_workdir:
                shutil.rmtree(workdir, ignore_errors=True)
            raise
        return LaunchedMicroVM(
            process=process,
            workdir=workdir,
            config_path=config_path,
            api_socket=api_socket,
            vsock_uds_path=config.vsock_uds_path,
        )

    @staticmethod
    def terminate(vm: LaunchedMicroVM, *, timeout: float = 5.0) -> None:
        """Stop the VMM process and remove its working directory."""
        process = vm.process
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        shutil.rmtree(vm.workdir, ignore_errors=True)
