"""Tests for the microVM backend scaffolding.

Booting a real guest needs KVM, which CI hosts generally lack, so these tests
exercise the pieces that do not require a hypervisor: VMM/KVM capability
detection, the fail-closed admission gate, the machine-config builder, and the
supervisor routing for ``backend="microvm"``.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.errors import SandboxError
from pyisolate.runtime import microvm

# -- capability detection ---------------------------------------------------


def test_detect_vmm_prefers_first_available(monkeypatch):
    monkeypatch.setattr(
        microvm.shutil,
        "which",
        lambda exe: "/usr/bin/firecracker" if exe == "firecracker" else None,
    )
    kind, path = microvm.detect_vmm()
    assert kind == "firecracker"
    assert path == "/usr/bin/firecracker"


def test_detect_vmm_falls_through_to_qemu(monkeypatch):
    monkeypatch.setattr(
        microvm.shutil,
        "which",
        lambda exe: (
            "/usr/bin/qemu-system-x86_64" if exe == "qemu-system-x86_64" else None
        ),
    )
    kind, path = microvm.detect_vmm()
    assert kind == "qemu"
    assert path.endswith("qemu-system-x86_64")


def test_detect_vmm_none_when_absent(monkeypatch):
    monkeypatch.setattr(microvm.shutil, "which", lambda exe: None)
    assert microvm.detect_vmm() == (None, None)


def test_kvm_available_true_when_accessible(monkeypatch):
    monkeypatch.setattr(microvm.os.path, "exists", lambda p: p == "/dev/kvm")
    monkeypatch.setattr(microvm.os, "access", lambda p, mode: True)
    assert microvm.kvm_available() is True


def test_kvm_available_false_when_missing(monkeypatch):
    monkeypatch.setattr(microvm.os.path, "exists", lambda p: False)
    assert microvm.kvm_available() is False


def test_detect_support_collects_reasons_when_nothing_available(monkeypatch):
    monkeypatch.setattr(microvm.shutil, "which", lambda exe: None)
    monkeypatch.setattr(microvm.os.path, "exists", lambda p: False)
    support = microvm.detect_microvm_support()
    assert support.ready is False
    assert support.vmm_kind is None
    joined = " ".join(support.reasons)
    assert "no supported VMM" in joined
    assert "/dev/kvm is not present" in joined


def test_detect_support_reports_inaccessible_kvm(monkeypatch):
    monkeypatch.setattr(microvm.shutil, "which", lambda exe: "/usr/bin/firecracker")
    monkeypatch.setattr(microvm.os.path, "exists", lambda p: True)
    monkeypatch.setattr(microvm.os, "access", lambda p, mode: False)
    support = microvm.detect_microvm_support()
    assert support.ready is False
    assert any("not readable+writable" in reason for reason in support.reasons)


def test_support_ready_and_as_dict(monkeypatch):
    monkeypatch.setattr(microvm.shutil, "which", lambda exe: "/usr/bin/firecracker")
    monkeypatch.setattr(microvm.os.path, "exists", lambda p: True)
    monkeypatch.setattr(microvm.os, "access", lambda p, mode: True)
    support = microvm.detect_microvm_support()
    assert support.ready is True
    payload = support.as_dict()
    assert payload["ready"] is True
    assert payload["vmm_kind"] == "firecracker"
    assert payload["kvm"] is True


# -- fail-closed admission --------------------------------------------------


def test_require_support_raises_with_reasons_when_not_ready():
    support = microvm.MicroVMSupport(
        vmm_kind=None, vmm_path=None, kvm=False, reasons=("no supported VMM on PATH",)
    )
    with pytest.raises(microvm.MicroVMUnavailable, match="no supported VMM on PATH"):
        microvm.require_microvm_support(support)


def test_require_support_returns_support_when_ready():
    support = microvm.MicroVMSupport(
        vmm_kind="firecracker", vmm_path="/usr/bin/firecracker", kvm=True
    )
    assert microvm.require_microvm_support(support) is support


def test_microvm_unavailable_is_a_sandbox_error():
    assert issubclass(microvm.MicroVMUnavailable, SandboxError)


# -- machine-config builder -------------------------------------------------


def test_config_rejects_invalid_sizing():
    kwargs = dict(kernel_image="/k", rootfs_image="/r", vsock_uds_path="/v.sock")
    with pytest.raises(ValueError):
        microvm.MicroVMConfig(vcpus=0, **kwargs)
    with pytest.raises(ValueError):
        microvm.MicroVMConfig(mem_size_mib=0, **kwargs)
    with pytest.raises(ValueError):
        microvm.MicroVMConfig(guest_cid=2, **kwargs)


def test_config_from_limits_rounds_memory_up():
    cfg = microvm.MicroVMConfig.from_limits(
        kernel_image="/k",
        rootfs_image="/r",
        vsock_uds_path="/v.sock",
        mem_bytes=(200 << 20) + 1,  # just over 200 MiB
    )
    assert cfg.mem_size_mib == 201


def test_config_from_limits_defaults_memory_when_unbounded():
    cfg = microvm.MicroVMConfig.from_limits(
        kernel_image="/k", rootfs_image="/r", vsock_uds_path="/v.sock"
    )
    assert cfg.mem_size_mib == 128


def test_to_firecracker_json_matches_schema():
    cfg = microvm.MicroVMConfig(
        kernel_image="/boot/vmlinux",
        rootfs_image="/img/rootfs.ext4",
        vsock_uds_path="/run/pyisolate/vm.sock",
        vcpus=2,
        mem_size_mib=256,
        guest_cid=7,
    )
    doc = cfg.to_firecracker_json()
    assert doc["boot-source"]["kernel_image_path"] == "/boot/vmlinux"
    assert doc["machine-config"] == {
        "vcpu_count": 2,
        "mem_size_mib": 256,
        "smt": False,
    }
    assert doc["vsock"] == {
        "guest_cid": 7,
        "uds_path": "/run/pyisolate/vm.sock",
    }
    root = doc["drives"][0]
    assert root["is_root_device"] is True
    assert root["path_on_host"] == "/img/rootfs.ext4"


# -- supervisor integration -------------------------------------------------


def test_spawn_microvm_fails_closed_when_unavailable(monkeypatch):
    monkeypatch.setattr(
        microvm,
        "detect_microvm_support",
        lambda: microvm.MicroVMSupport(
            vmm_kind=None,
            vmm_path=None,
            kvm=False,
            reasons=("no supported VMM on PATH", "/dev/kvm is not present"),
        ),
    )
    with pytest.raises(microvm.MicroVMUnavailable, match="/dev/kvm"):
        iso.spawn("vm", backend="microvm")


def test_spawn_microvm_reports_pending_launcher_when_host_ready(monkeypatch):
    monkeypatch.setattr(
        microvm,
        "detect_microvm_support",
        lambda: microvm.MicroVMSupport(
            vmm_kind="firecracker", vmm_path="/usr/bin/firecracker", kvm=True
        ),
    )
    with pytest.raises(NotImplementedError, match="launcher"):
        iso.spawn("vm", backend="microvm")


def test_microvm_is_a_supported_but_unimplemented_backend():
    from pyisolate.supervisor import IMPLEMENTED_BACKENDS, SUPPORTED_BACKENDS

    assert "microvm" in SUPPORTED_BACKENDS
    # It is routed to a dedicated fail-closed path, not the generic
    # implemented-backend list.
    assert "microvm" not in IMPLEMENTED_BACKENDS
