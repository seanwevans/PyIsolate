"""Build provenance and platform feature detection helpers."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import sysconfig
from pathlib import Path
from typing import Any


def _safe_read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _safe_sha256(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def python_build_provenance() -> dict[str, Any]:
    """Return metadata that identifies the exact interpreter build."""

    executable = Path(sys.executable).resolve()
    return {
        "executable": str(executable),
        "executable_sha256": _safe_sha256(str(executable)),
        "version": sys.version,
        "cache_tag": sys.implementation.cache_tag,
        "abiflags": getattr(sys, "abiflags", ""),
        "platform": sysconfig.get_platform(),
        "soabi": sysconfig.get_config_var("SOABI"),
        "configure_args": sysconfig.get_config_var("CONFIG_ARGS"),
        "py_gil_disabled": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
        "cflags": sysconfig.get_config_var("CFLAGS"),
        "ldflags": sysconfig.get_config_var("LDFLAGS"),
    }


def kernel_feature_flags() -> dict[str, dict[str, Any]]:
    """Probe host kernel capabilities and report degradations clearly."""

    lsm = (_safe_read_text("/sys/kernel/security/lsm") or "").split(",")
    return {
        "ebpf_lsm": {
            "available": "bpf" in lsm,
            "reason": "Kernel LSM list does not include bpf" if "bpf" not in lsm else "ok",
        },
        "bpffs": {
            "available": os.path.ismount("/sys/fs/bpf"),
            "reason": "/sys/fs/bpf is not mounted" if not os.path.ismount("/sys/fs/bpf") else "ok",
        },
        "cgroup_v2": {
            "available": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
            "reason": "cgroup v2 controllers file missing"
            if not Path("/sys/fs/cgroup/cgroup.controllers").exists()
            else "ok",
        },
        "io_uring": {
            "available": hasattr(os, "SYS_io_uring_setup") or platform.system() == "Linux",
            "reason": "non-Linux kernels are unsupported for io_uring"
            if platform.system() != "Linux"
            else "ok",
        },
        "landlock": {
            "available": Path("/sys/kernel/security/landlock").exists(),
            "reason": "Landlock securityfs entry not detected"
            if not Path("/sys/kernel/security/landlock").exists()
            else "ok",
        },
    }


def hardening_feature_flags() -> dict[str, dict[str, Any]]:
    """Return installation-time hardening state with explicit fallback status."""

    provenance = python_build_provenance()
    return {
        "no_gil_runtime": {
            "available": bool(provenance["py_gil_disabled"]),
            "reason": "Python was not built with --disable-gil"
            if not provenance["py_gil_disabled"]
            else "ok",
        },
        "deterministic_wheels": {
            "available": platform.system() == "Linux"
            and platform.machine() in {"x86_64", "aarch64"},
            "reason": "Deterministic wheel policy only defined for Linux x86_64/aarch64"
            if not (platform.system() == "Linux" and platform.machine() in {"x86_64", "aarch64"})
            else "ok",
        },
    }


def installation_report() -> dict[str, Any]:
    """Compose a machine-readable report for release/debug tooling."""

    return {
        "python": python_build_provenance(),
        "kernel": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "features": kernel_feature_flags(),
        },
        "hardening": hardening_feature_flags(),
    }


def installation_report_json() -> str:
    return json.dumps(installation_report(), indent=2, sort_keys=True)
