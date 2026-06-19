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
class GradeComponent:
    """Scored status for one host guarantee area."""

    key: str
    label: str
    score: int
    max_score: int
    active: bool
    details: str
    evidence: dict[str, object]


@dataclass
class GradeReport:
    """Machine-readable conformance score for active PyIsolate guarantees."""

    score: int
    max_score: int
    percent: float
    generated_at_epoch_s: int
    host: str
    components: list[GradeComponent]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["components"] = [asdict(c) for c in self.components]
        payload["active_guarantees"] = [c.key for c in self.components if c.active]
        payload["inactive_guarantees"] = [
            c.key for c in self.components if not c.active
        ]
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


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

    def grade(self) -> GradeReport:
        """Return a scored report of which PyIsolate guarantees are active."""

        python_build = self._probe_python_build()
        bpf_availability = self._probe_bpf_availability()
        cgroup_behavior = self._probe_cgroup_behavior()
        policy_enforcement = self._probe_policy_enforcement()
        quota_enforcement = self._probe_timeout_and_kill_behavior()
        ebpf_lsm = self._probe_ebpf_lsm(bpf_availability)
        landlock_fallback = self._probe_landlock_fallback(ebpf_lsm.passed)
        no_gil_extension_safety = self._probe_no_gil_extension_safety(
            python_build, policy_enforcement
        )
        broker_crypto = self._probe_broker_crypto()
        crash_isolation = self._probe_crash_isolation()

        probe_components = [
            (
                "free_threading",
                "free-threading",
                python_build,
                bool(python_build.evidence.get("py_gil_disabled"))
                and sys.version_info >= (3, 13),
            ),
            ("ebpf_lsm", "eBPF-LSM", ebpf_lsm, ebpf_lsm.passed),
            ("cgroup_v2", "cgroup v2", cgroup_behavior, cgroup_behavior.passed),
            (
                "landlock_fallback",
                "Landlock fallback",
                landlock_fallback,
                landlock_fallback.passed,
            ),
            (
                "no_gil_extension_safety",
                "no-GIL extension safety",
                no_gil_extension_safety,
                no_gil_extension_safety.passed,
            ),
            ("broker_crypto", "broker crypto", broker_crypto, broker_crypto.passed),
            (
                "quota_enforcement",
                "quota enforcement",
                quota_enforcement,
                quota_enforcement.passed,
            ),
            (
                "crash_isolation",
                "crash isolation",
                crash_isolation,
                crash_isolation.passed,
            ),
        ]
        components = [
            GradeComponent(
                key=key,
                label=label,
                score=1 if active else 0,
                max_score=1,
                active=active,
                details=probe.details,
                evidence=probe.evidence,
            )
            for key, label, probe, active in probe_components
        ]
        score = sum(component.score for component in components)
        max_score = sum(component.max_score for component in components)
        percent = round((score / max_score) * 100, 1) if max_score else 0.0
        return GradeReport(
            score=score,
            max_score=max_score,
            percent=percent,
            generated_at_epoch_s=int(time.time()),
            host=platform.node() or "unknown",
            components=components,
        )

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
            name: bool(caps_value & (1 << bit)) for name, bit in CAPABILITY_BITS.items()
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
                if (
                    len(fields) >= 3
                    and fields[1] == "/sys/fs/bpf"
                    and fields[2] == "bpf"
                ):
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

    def _probe_ebpf_lsm(
        self, bpf_availability: ProbeResult | None = None
    ) -> ProbeResult:
        lsm_path = Path("/sys/kernel/security/lsm")
        lsm_entries: list[str] = []
        if lsm_path.exists():
            lsm_entries = [
                entry
                for entry in lsm_path.read_text(encoding="utf-8").strip().split(",")
                if entry
            ]
        if bpf_availability is None:
            bpf_availability = self._probe_bpf_availability()
        has_bpf_lsm = "bpf" in lsm_entries
        passed = has_bpf_lsm and bpf_availability.passed
        return ProbeResult(
            name="ebpf_lsm",
            passed=passed,
            required=True,
            details="BPF LSM hook and BPF toolchain are available for kernel policy enforcement",
            evidence={
                "lsm_path": str(lsm_path),
                "lsm_entries": lsm_entries,
                "bpf_lsm_enabled": has_bpf_lsm,
                "bpf_availability": bpf_availability.evidence,
            },
        )

    def _probe_landlock_fallback(self, ebpf_lsm_active: bool = False) -> ProbeResult:
        landlock_path = Path("/sys/kernel/security/landlock")
        available = landlock_path.exists()
        return ProbeResult(
            name="landlock_fallback",
            passed=available,
            required=False,
            details="Landlock fallback is available when privileged eBPF-LSM enforcement is inactive",
            evidence={
                "landlock_path": str(landlock_path),
                "available": available,
                "fallback_active": available and not ebpf_lsm_active,
                "ebpf_lsm_active": ebpf_lsm_active,
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
            attached = threads_file.exists() and str(
                os.gettid()
            ) in threads_file.read_text(encoding="utf-8")
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

    def _probe_no_gil_extension_safety(
        self,
        python_build: ProbeResult | None = None,
        policy_enforcement: ProbeResult | None = None,
    ) -> ProbeResult:
        if python_build is None:
            python_build = self._probe_python_build()
        if policy_enforcement is None:
            policy_enforcement = self._probe_policy_enforcement()
        blocked_native_loader = False
        from pyisolate.errors import PolicyError

        with iso.spawn(
            "conformance-native-loader", allowed_imports=["math"]
        ) as sandbox:
            sandbox.exec("import ctypes")
            try:
                sandbox.recv(timeout=1)
            except PolicyError:
                blocked_native_loader = True
            except Exception:
                blocked_native_loader = False
        gil_disabled = bool(python_build.evidence.get("py_gil_disabled"))
        passed = gil_disabled and policy_enforcement.passed and blocked_native_loader
        return ProbeResult(
            name="no_gil_extension_safety",
            passed=passed,
            required=True,
            details="Free-threaded Python is active and sandbox policy blocks unaudited native loaders",
            evidence={
                "py_gil_disabled": gil_disabled,
                "policy_enforcement_passed": policy_enforcement.passed,
                "blocked_ctypes_import": blocked_native_loader,
                "compatibility_matrix": "docs/compatibility-matrix.md",
            },
        )

    def _probe_broker_crypto(self) -> ProbeResult:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519

        from pyisolate.broker.crypto import CryptoBroker

        priv_a = x25519.X25519PrivateKey.generate()
        priv_b = x25519.X25519PrivateKey.generate()
        priv_a_bytes = priv_a.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        priv_b_bytes = priv_b.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_a = priv_a.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        pub_b = priv_b.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        broker_a = CryptoBroker(priv_a_bytes, pub_b, max_frame_len=64)
        broker_b = CryptoBroker(priv_b_bytes, pub_a, max_frame_len=64)
        frame = broker_a.frame(b"doctor-grade")
        roundtrip = broker_b.unframe(frame) == b"doctor-grade"
        replay_blocked = False
        oversized_blocked = False
        try:
            broker_b.unframe(frame)
        except ValueError:
            replay_blocked = True
        large_frame = broker_a.frame(b"x") + (b"x" * 128)
        try:
            broker_b.unframe(large_frame)
        except ValueError:
            oversized_blocked = True
        passed = roundtrip and replay_blocked and oversized_blocked
        return ProbeResult(
            name="broker_crypto",
            passed=passed,
            required=True,
            details="Broker channel authenticates AEAD frames and rejects replay/oversized frames",
            evidence={
                "key_exchange": "X25519",
                "aead": "ChaCha20-Poly1305",
                "roundtrip": roundtrip,
                "replay_blocked": replay_blocked,
                "oversized_frame_blocked": oversized_blocked,
            },
        )

    def _probe_crash_isolation(self) -> ProbeResult:
        from pyisolate.errors import SandboxError

        exception_isolated = False
        supervisor_survived = False
        with iso.spawn("conformance-crash") as sandbox:
            sandbox.exec("raise RuntimeError('guest crash')")
            try:
                sandbox.recv(timeout=1)
            except SandboxError:
                exception_isolated = True
            except Exception:
                exception_isolated = False
        with iso.spawn("conformance-crash-survivor") as sandbox:
            sandbox.exec("post('alive')")
            supervisor_survived = sandbox.recv(timeout=1) == "alive"
        passed = exception_isolated and supervisor_survived
        return ProbeResult(
            name="crash_isolation",
            passed=passed,
            required=True,
            details="Guest exceptions are contained and the supervisor can launch a fresh sandbox",
            evidence={
                "guest_exception_isolated": exception_isolated,
                "supervisor_survived": supervisor_survived,
            },
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

    parser = argparse.ArgumentParser(
        description="Run PyIsolate host conformance checks"
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    parser.add_argument(
        "--grade", action="store_true", help="emit scored guarantee report"
    )
    args = parser.parse_args(argv)

    if args.grade:
        grade = ConformanceSuite().grade()
        print(grade.to_json())
        return 0

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
