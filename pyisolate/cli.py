"""Top-level ``pyisolate`` command."""

from __future__ import annotations

import argparse
import sys

from . import doctor


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pyisolate")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("doctor", help="Run installation and no-GIL diagnostics")

    argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(argv[:1])
    if args.command is None:
        parser.print_help()
        raise SystemExit(2)
    if args.command == "doctor":
        doctor.main(argv[1:])
        return
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    main()
