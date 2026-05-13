"""CLI utilities for installation diagnostics."""

from __future__ import annotations

import argparse
import json
from typing import Any

from .nogil import imported_native_extensions, no_gil_readiness_report
from .provenance import installation_report_json


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
    print(installation_report_json())


if __name__ == "__main__":
    main()
