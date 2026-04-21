"""CLI utilities for installation diagnostics."""

from __future__ import annotations

import argparse

from .provenance import installation_report_json


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="pyisolate-doctor",
        description="Print PyIsolate build provenance and kernel feature flags.",
    )
    parser.parse_args(argv)
    print(installation_report_json())


if __name__ == "__main__":
    main()
