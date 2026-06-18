"""CLI utilities for installation diagnostics."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .provenance import installation_report

HARDENED_REQUIRED_KERNEL_FEATURES = ("ebpf_lsm", "bpffs", "cgroup_v2")
HARDENED_REQUIRED_BPF_TOOLS = ("clang", "bpftool", "llvm_objdump")


def _failure(message: str, *, check: str, reason: str) -> dict[str, str]:
    return {"check": check, "message": message, "reason": reason}


def hardened_failures(report: dict[str, Any]) -> list[dict[str, str]]:
    """Return hard failures that make hardened mode unsupported on this host."""

    failures: list[dict[str, str]] = []
    python = report.get("python", {})
    if not python.get("py_gil_disabled"):
        failures.append(
            _failure(
                "hardened mode requires a CPython build configured with --disable-gil",
                check="python.no_gil_runtime",
                reason="Py_GIL_DISABLED is not set for the active interpreter",
            )
        )

    kernel = report.get("kernel", {})
    if kernel.get("system") != "Linux":
        failures.append(
            _failure(
                "hardened mode requires a Linux kernel",
                check="kernel.system",
                reason=f"detected {kernel.get('system') or 'unknown'}",
            )
        )

    kernel_features = kernel.get("features", {})
    for name in HARDENED_REQUIRED_KERNEL_FEATURES:
        feature = kernel_features.get(name, {})
        if not feature.get("available"):
            failures.append(
                _failure(
                    f"hardened mode requires kernel feature {name}",
                    check=f"kernel.features.{name}",
                    reason=str(feature.get("reason") or "not reported"),
                )
            )

    bpf_tools = report.get("bpf", {}).get("toolchain", {})
    for name in HARDENED_REQUIRED_BPF_TOOLS:
        tool = bpf_tools.get(name, {})
        if not tool.get("available"):
            failures.append(
                _failure(
                    f"hardened mode requires BPF tool {tool.get('command') or name}",
                    check=f"bpf.toolchain.{name}",
                    reason=str(tool.get("reason") or "not reported"),
                )
            )

    return failures


def doctor_report(*, mode: str = "dev") -> dict[str, Any]:
    """Return installation diagnostics plus mode-specific gate results."""

    report = installation_report()
    failures = hardened_failures(report) if mode == "hardened" else []
    report["doctor"] = {
        "mode": mode,
        "status": "fail" if failures else "pass",
        "failures": failures,
    }
    return report


def doctor_report_json(*, mode: str = "dev") -> str:
    return json.dumps(doctor_report(mode=mode), indent=2, sort_keys=True)


def assert_hardened_supported(report: dict[str, Any] | None = None) -> None:
    """Raise RuntimeError if this host cannot run PyIsolate hardened mode."""

    active_report = installation_report() if report is None else report
    failures = hardened_failures(active_report)
    if failures:
        details = "; ".join(
            f"{failure['check']}: {failure['reason']}" for failure in failures
        )
        raise RuntimeError(f"PyIsolate hardened mode is unsupported: {details}")
from .conformance import ConformanceSuite
from .nogil import imported_native_extensions, no_gil_readiness_report


def _print_json(payload: object) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _print_gil_human(report: dict[str, Any]) -> None:
    axis = report["axis"]
    build = report["build"]
    runtime = report["runtime"]
    extensions = report["extensions"]
    print(f"mode: {axis['mode']}")
    print(f"parallel_cells_ready: {axis['parallel_cells_ready']}")
    print(f"reason: {axis['reason']}")
    print(f"py_gil_disabled: {build['py_gil_disabled']}")
    print(f"gil_enabled: {runtime['gil_enabled']}")
    print(f"loaded_native_extensions: {extensions['loaded_native_count']}")
    print(f"unknown_or_unmarked_extensions: {extensions['unknown_or_unmarked_count']}")


def _print_extensions_human(extensions: list[dict[str, object]]) -> None:
    if not extensions:
        print("No imported native extension modules detected.")
        return
    for item in extensions:
        marker = "OK" if item["no_gil_safe"] else "UNKNOWN"
        print(f"{marker}\t{item['name']}\t{item['origin']}\t{item['reason']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pyisolate-doctor",
        description="Print PyIsolate build provenance and kernel/no-GIL feature flags.",
    )
    parser.add_argument(
        "--grade",
        action="store_true",
        help="emit a scored report of active PyIsolate guarantees",
    )
    parser.add_argument(
        "--mode",
        choices=("dev", "hardened"),
        default="dev",
        help="Validate requirements for the selected rollout mode.",
    )
    subparsers = parser.add_subparsers(dest="command")

    gil_parser = subparsers.add_parser(
        "gil",
        help="Report whether this host can run PyIsolate as parallel cells.",
    )
    gil_parser.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON"
    )

    ext_parser = subparsers.add_parser(
        "extensions",
        help="List loaded native extensions and their no-GIL audit status.",
    )
    ext_parser.add_argument(
        "--json", action="store_true", help="Print machine-readable JSON"
    )

    args = parser.parse_args(argv)

    if args.command == "gil":
        report = no_gil_readiness_report()
        if args.json:
            _print_json(report)
        else:
            _print_gil_human(report)
        return

    if args.command == "extensions":
        extensions = imported_native_extensions()
        if args.json:
            _print_json({"extensions": extensions})
        else:
            _print_extensions_human(extensions)
        return

    if args.grade:
        print(ConformanceSuite().grade().to_json())
        return

    report = doctor_report(mode=args.mode)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.mode == "hardened" and report["doctor"]["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
