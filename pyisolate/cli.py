"""Top-level ``pyisolate`` command."""

from __future__ import annotations

import argparse
import sys

from . import doctor


def _run_doctor(args: argparse.Namespace) -> None:
    doctor.main(args.doctor_args)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="pyisolate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor_parser = subparsers.add_parser(
        "doctor", help="Run installation and no-GIL diagnostics"
    )
    doctor_parser.add_argument("doctor_args", nargs=argparse.REMAINDER)
    doctor_parser.set_defaults(func=_run_doctor)

    argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
