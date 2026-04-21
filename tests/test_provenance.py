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
