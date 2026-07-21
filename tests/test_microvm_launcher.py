"""Tests for the microVM VMM launcher (config materialization + lifecycle).

Booting a real guest needs KVM and a guest image, so these tests drive the
launcher against a *fake VMM* -- a tiny script that ignores its arguments and
sleeps -- to exercise config materialization, command construction, and the
process lifecycle without a hypervisor.
"""

import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

from pyisolate.runtime import microvm


def _fake_vmm(tmp_path: Path) -> str:
    """A stand-in VMM executable that ignores args and stays alive."""
    script = tmp_path / "fake-vmm"
    script.write_text("#!/bin/sh\nexec sleep 30\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


def _config(tmp_path: Path) -> microvm.MicroVMConfig:
    return microvm.MicroVMConfig(
        kernel_image="/boot/vmlinux",
        rootfs_image="/img/rootfs.ext4",
        vsock_uds_path=str(tmp_path / "vm.sock"),
        vcpus=2,
        mem_size_mib=256,
    )


def _ready_support(vmm_path: str) -> microvm.MicroVMSupport:
    return microvm.MicroVMSupport(vmm_kind="firecracker", vmm_path=vmm_path, kvm=True)


# -- command construction ---------------------------------------------------


def test_build_command_for_firecracker():
    support = _ready_support("/usr/bin/firecracker")
    launcher = microvm.MicroVMLauncher(support)
    cmd = launcher.build_command("/tmp/cfg.json", "/tmp/api.sock")
    assert cmd == [
        "/usr/bin/firecracker",
        "--api-sock",
        "/tmp/api.sock",
        "--config-file",
        "/tmp/cfg.json",
    ]


def test_build_command_rejects_unimplemented_vmm():
    support = microvm.MicroVMSupport(
        vmm_kind="qemu", vmm_path="/usr/bin/qemu-system-x86_64", kvm=True
    )
    launcher = microvm.MicroVMLauncher(support)
    with pytest.raises(microvm.MicroVMUnavailable, match="not implemented"):
        launcher.build_command("/tmp/cfg.json", "/tmp/api.sock")


def test_build_command_requires_a_vmm_path():
    support = microvm.MicroVMSupport(vmm_kind=None, vmm_path=None, kvm=True)
    launcher = microvm.MicroVMLauncher(support)
    with pytest.raises(microvm.MicroVMUnavailable):
        launcher.build_command("/tmp/cfg.json", "/tmp/api.sock")


# -- launch / lifecycle -----------------------------------------------------


def test_launch_writes_config_and_starts_process(tmp_path):
    launcher = microvm.MicroVMLauncher(_ready_support(_fake_vmm(tmp_path)))
    config = _config(tmp_path)
    vm = launcher.launch(config)
    try:
        assert vm.is_alive()
        assert vm.pid > 0
        # The config file is materialized in the VM's workdir and matches the
        # Firecracker document the config renders.
        with open(vm.config_path, encoding="utf-8") as handle:
            written = json.load(handle)
        assert written == config.to_firecracker_json()
        assert os.path.dirname(vm.config_path) == vm.workdir
        assert vm.api_socket.startswith(vm.workdir)
    finally:
        microvm.MicroVMLauncher.terminate(vm)


def test_terminate_stops_process_and_removes_workdir(tmp_path):
    launcher = microvm.MicroVMLauncher(_ready_support(_fake_vmm(tmp_path)))
    vm = launcher.launch(_config(tmp_path))
    workdir = vm.workdir
    assert os.path.isdir(workdir)
    microvm.MicroVMLauncher.terminate(vm)
    assert not vm.is_alive()
    assert not os.path.exists(workdir)


def test_terminate_is_safe_after_process_exit(tmp_path):
    launcher = microvm.MicroVMLauncher(_ready_support(_fake_vmm(tmp_path)))
    vm = launcher.launch(_config(tmp_path))
    vm.process.kill()
    vm.process.wait()
    # Already dead: terminate must not raise and must still clean up.
    microvm.MicroVMLauncher.terminate(vm)
    assert not os.path.exists(vm.workdir)


def test_launch_cleans_up_workdir_on_failure(tmp_path, monkeypatch):
    # A non-Firecracker VMM fails in build_command *after* the workdir is made;
    # the owned workdir must be removed rather than leaked.
    support = microvm.MicroVMSupport(
        vmm_kind="cloud-hypervisor", vmm_path="/usr/bin/cloud-hypervisor", kvm=True
    )
    launcher = microvm.MicroVMLauncher(support)
    created = []
    real_mkdtemp = microvm.tempfile.mkdtemp

    def _tracking_mkdtemp(*args, **kwargs):
        path = real_mkdtemp(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr(microvm.tempfile, "mkdtemp", _tracking_mkdtemp)
    with pytest.raises(microvm.MicroVMUnavailable):
        launcher.launch(_config(tmp_path))
    assert created, "launch should have created a workdir before failing"
    assert not os.path.exists(created[0])
