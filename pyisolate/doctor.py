"""CLI utilities for installation diagnostics."""

from __future__ import annotations

import argparse

from .conformance import ConformanceSuite
from .provenance import installation_report_json


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pyisolate-doctor",
        description="Print PyIsolate build provenance and kernel feature flags.",
    )
    parser.add_argument(
        "--grade",
        action="store_true",
        help="emit a scored report of active PyIsolate guarantees",
    )
    args = parser.parse_args(argv)
    if args.grade:
        print(ConformanceSuite().grade().to_json())
        return
    print(installation_report_json())


if __name__ == "__main__":
    main()
