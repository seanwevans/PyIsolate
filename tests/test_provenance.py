import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import json

from pyisolate.doctor import main
from pyisolate.provenance import installation_report


def test_installation_report_schema():
    report = installation_report()
    assert "python" in report
    assert "kernel" in report
    assert "hardening" in report
    assert isinstance(report["python"]["executable_sha256"], (str, type(None)))


def test_doctor_cli_output(capsys):
    main([])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "kernel" in payload
    assert "features" in payload["kernel"]


def test_doctor_hardened_mode_fails_closed(monkeypatch, capsys):
    def fake_report():
        return {
            "python": {"py_gil_disabled": False},
            "kernel": {
                "system": "Linux",
                "features": {
                    "ebpf_lsm": {"available": False, "reason": "missing bpf lsm"},
                    "bpffs": {"available": True, "reason": "ok"},
                    "cgroup_v2": {"available": True, "reason": "ok"},
                },
            },
            "bpf": {
                "toolchain": {
                    "clang": {"available": True, "command": "clang", "reason": "ok"},
                    "bpftool": {
                        "available": False,
                        "command": "bpftool",
                        "reason": "bpftool not found on PATH",
                    },
                    "llvm_objdump": {
                        "available": True,
                        "command": "llvm-objdump",
                        "reason": "ok",
                    },
                }
            },
            "hardening": {},
        }

    monkeypatch.setattr("pyisolate.doctor.installation_report", fake_report)

    try:
        main(["--mode", "hardened"])
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("hardened doctor should fail closed")

    payload = json.loads(capsys.readouterr().out)
    assert payload["doctor"]["status"] == "fail"
    checks = {failure["check"] for failure in payload["doctor"]["failures"]}
    assert "python.no_gil_runtime" in checks
    assert "kernel.features.ebpf_lsm" in checks
    assert "bpf.toolchain.bpftool" in checks


def test_doctor_hardened_mode_passes_supported_report(monkeypatch, capsys):
    def fake_report():
        return {
            "python": {"py_gil_disabled": True},
            "kernel": {
                "system": "Linux",
                "features": {
                    "ebpf_lsm": {"available": True, "reason": "ok"},
                    "bpffs": {"available": True, "reason": "ok"},
                    "cgroup_v2": {"available": True, "reason": "ok"},
                },
            },
            "bpf": {
                "toolchain": {
                    "clang": {"available": True, "command": "clang", "reason": "ok"},
                    "bpftool": {
                        "available": True,
                        "command": "bpftool",
                        "reason": "ok",
                    },
                    "llvm_objdump": {
                        "available": True,
                        "command": "llvm-objdump",
                        "reason": "ok",
                    },
                }
            },
            "hardening": {},
        }

    monkeypatch.setattr("pyisolate.doctor.installation_report", fake_report)

    main(["--mode", "hardened"])

    payload = json.loads(capsys.readouterr().out)
    assert payload["doctor"] == {
        "mode": "hardened",
        "status": "pass",
        "failures": [],
    }
