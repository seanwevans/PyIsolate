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


def test_installation_report_exposes_no_gil_axis():
    report = installation_report()
    assert report["no_gil"]["axis"]["mode"] in {
        "parallel_cells",
        "scheduled_compartments",
    }
    assert "parallel_cells_ready" in report["no_gil"]["axis"]


def test_doctor_gil_cli_output(capsys):
    main(["gil"])
    captured = capsys.readouterr()
    assert "mode:" in captured.out
    assert "parallel_cells_ready:" in captured.out


def test_doctor_extensions_json_output(capsys):
    main(["extensions", "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "extensions" in payload


def test_top_level_pyisolate_doctor_gil(capsys):
    from pyisolate.cli import main as cli_main

    cli_main(["doctor", "gil"])
    captured = capsys.readouterr()
    assert "parallel_cells_ready:" in captured.out
