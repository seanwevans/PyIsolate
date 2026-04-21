"""Host conformance suite for PyIsolate guarantees.

The checks in this module are intentionally operational: they probe host/runtime
behavior and emit a machine-readable report to help answer whether a host
satisfies PyIsolate's baseline guarantees.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import sysconfig
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

import pyisolate as iso

CAPABILITY_BITS = {
    "CAP_SYS_ADMIN": 21,
    "CAP_PERFMON": 38,
    "CAP_BPF": 39,
}


@dataclass
class ProbeResult:
    """Result for a single conformance probe."""

    name: str
    passed: bool
    required: bool
    details: str
    evidence: dict[str, object]


@dataclass
class ConformanceReport:
    """Structured result for a full conformance run."""

    passed: bool
    required_passed: int
    required_total: int
    optional_passed: int
    optional_total: int
    generated_at_epoch_s: int
    host: str
    probes: list[ProbeResult]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["probes"] = [asdict(p) for p in self.probes]
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class ConformanceSuite:
    """Runs host-level probes that back PyIsolate guarantee claims."""

    def run(self) -> ConformanceReport:
        probes = [
            self._probe_python_build(),
            self._probe_kernel_capabilities(),
            self._probe_bpf_availability(),
            self._probe_cgroup_behavior(),
            self._probe_policy_enforcement(),
            self._probe_timeout_and_kill_behavior(),
        ]
        required = [p for p in probes if p.required]
        optional = [p for p in probes if not p.required]
        required_passed = sum(1 for p in required if p.passed)
        optional_passed = sum(1 for p in optional if p.passed)
        passed = required_passed == len(required)
        return ConformanceReport(
            passed=passed,
            required_passed=required_passed,
            required_total=len(required),
            optional_passed=optional_passed,
            optional_total=len(optional),
            generated_at_epoch_s=int(time.time()),
            host=platform.node() or "unknown",
            probes=probes,
        )

    def _probe_python_build(self) -> ProbeResult:
        gil_disabled = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
        interpreters_available = hasattr(sys, "implementation") and (
            sys.version_info >= (3, 13)
        )
        passed = sys.version_info >= (3, 11)
        details = "Python runtime satisfies minimum version for PyIsolate"
        if not passed:
            details = "Python runtime is below PyIsolate minimum"
        return ProbeResult(
            name="python_build",
            passed=passed,
            required=True,
            details=details,
            evidence={
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation(),
                "py_gil_disabled": gil_disabled,
                "subinterpreter_ready_hint": interpreters_available,
            },
        )

    def _probe_kernel_capabilities(self) -> ProbeResult:
        status = Path("/proc/self/status")
        caps_hex = "0"
        if status.exists():
            for line in status.read_text(encoding="utf-8").splitlines():
                if line.startswith("CapEff:"):
                    _, value = line.split(":", maxsplit=1)
                    caps_hex = value.strip()
                    break
        caps_value = int(caps_hex, 16)
        present = {
            name: bool(caps_value & (1 << bit))
            for name, bit in CAPABILITY_BITS.items()
        }
        passed = all(present.values())
        return ProbeResult(
            name="kernel_capabilities",
            passed=passed,
            required=False,
            details="Effective Linux capabilities required for full eBPF enforcement",
            evidence={
                "platform": platform.system(),
                "effective_caps_hex": caps_hex,
                "capabilities": present,
            },
        )

    def _probe_bpf_availability(self) -> ProbeResult:
        tools = {
            "clang": shutil.which("clang"),
            "bpftool": shutil.which("bpftool"),
            "llvm-objdump": shutil.which("llvm-objdump"),
        }
        tool_ok = all(tools.values())
        bpffs_mounted = False
        mounts = Path("/proc/mounts")
        if mounts.exists():
            for line in mounts.read_text(encoding="utf-8").splitlines():
                fields = line.split()
                if len(fields) >= 3 and fields[1] == "/sys/fs/bpf" and fields[2] == "bpf":
                    bpffs_mounted = True
                    break
        bpftool_works = False
        if tools["bpftool"]:
            result = subprocess.run(
                ["bpftool", "version"],
                check=False,
                capture_output=True,
                text=True,
            )
            bpftool_works = result.returncode == 0
        passed = tool_ok and bpffs_mounted and bpftool_works
        return ProbeResult(
            name="bpf_availability",
            passed=passed,
            required=True,
            details="Toolchain and bpffs availability for compiling/loading BPF programs",
            evidence={
                "tools": tools,
                "bpffs_mounted": bpffs_mounted,
                "bpftool_operational": bpftool_works,
            },
        )

    def _probe_cgroup_behavior(self) -> ProbeResult:
        from pyisolate import cgroup

        is_v2 = Path("/sys/fs/cgroup/cgroup.controllers").exists()
        test_name = f"conformance-{uuid.uuid4().hex[:8]}"
        cg_path = cgroup.create(test_name)
        created = cg_path is not None and Path(cg_path).exists()
        attached = False
        deleted = False
        if created:
            cgroup.attach_current(cg_path)
            threads_file = Path(cg_path) / "cgroup.threads"
            attached = threads_file.exists() and str(os.gettid()) in threads_file.read_text(
                encoding="utf-8"
            )
            cgroup.delete(cg_path)
            deleted = not Path(cg_path).exists()
        passed = bool(is_v2 and created and attached and deleted)
        return ProbeResult(
            name="cgroup_behavior",
            passed=passed,
            required=True,
            details="Can create, attach, and delete cgroup v2 controls",
            evidence={
                "cgroup_v2": is_v2,
                "created": created,
                "attached": attached,
                "deleted": deleted,
                "path": str(cg_path) if cg_path else None,
            },
        )

    def _probe_policy_enforcement(self) -> ProbeResult:
        from pyisolate.errors import PolicyError

        blocked_import = False
        with iso.spawn("conformance-policy", allowed_imports=["math"]) as sandbox:
            sandbox.exec("import os")
            try:
                sandbox.recv(timeout=1)
            except PolicyError:
                blocked_import = True
            except Exception:
                blocked_import = False
        return ProbeResult(
            name="policy_enforcement",
            passed=blocked_import,
            required=True,
            details="Sandbox policy blocks imports outside allow-list",
            evidence={"blocked_disallowed_import": blocked_import},
        )

    def _probe_timeout_and_kill_behavior(self) -> ProbeResult:
        from pyisolate.errors import CPUExceeded, TimeoutError

        timeout_triggered = False
        cpu_kill_triggered = False
        with iso.spawn("conformance-timeout") as sandbox:
            try:
                sandbox.recv(timeout=0.02)
            except TimeoutError:
                timeout_triggered = True
            except Exception:
                timeout_triggered = False

        with iso.spawn("conformance-quota", cpu_ms=1) as sandbox:
            sandbox.exec("while True: pass")
            try:
                sandbox.recv(timeout=1)
            except CPUExceeded:
                cpu_kill_triggered = True
            except Exception:
                cpu_kill_triggered = False

        passed = timeout_triggered and cpu_kill_triggered
        return ProbeResult(
            name="timeout_and_kill_behavior",
            passed=passed,
            required=True,
            details="Message timeouts and CPU quota kills are enforced",
            evidence={
                "recv_timeout_triggered": timeout_triggered,
                "cpu_quota_kill_triggered": cpu_kill_triggered,
            },
        )


def run_conformance_suite() -> ConformanceReport:
    """Execute all conformance probes and return a report."""

    return ConformanceSuite().run()


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for host conformance checks."""

    parser = argparse.ArgumentParser(description="Run PyIsolate host conformance checks")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    report = run_conformance_suite()
    if args.json:
        print(report.to_json())
    else:
        status = "PASS" if report.passed else "FAIL"
        print(f"PyIsolate host conformance: {status}")
        print(
            f"Required probes: {report.required_passed}/{report.required_total}; "
            f"Optional probes: {report.optional_passed}/{report.optional_total}"
        )
        for probe in report.probes:
            marker = "PASS" if probe.passed else "FAIL"
            required = "required" if probe.required else "optional"
            print(f" - [{marker}] {probe.name} ({required}): {probe.details}")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
