"""Top-level ``pyisolate`` command."""

from __future__ import annotations

import argparse

from . import doctor


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pyisolate")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("doctor", help="Run installation and no-GIL diagnostics")
    args, rest = parser.parse_known_args(argv)
    if args.command == "doctor":
        doctor.main(rest)
        return
    parser.print_help()


if __name__ == "__main__":
    main()
