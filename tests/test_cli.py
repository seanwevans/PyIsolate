import pytest

from pyisolate import cli


def test_pyisolate_doctor_delegates_to_doctor_main(monkeypatch):
    calls = []

    def fake_doctor_main(argv):
        calls.append(argv)

    monkeypatch.setattr(cli.doctor, "main", fake_doctor_main)

    cli.main(["doctor", "gil", "--json"])

    assert calls == [["gil", "--json"]]


def test_pyisolate_no_command_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main([])

    assert excinfo.value.code != 0
    captured = capsys.readouterr()
    assert "usage: pyisolate" in captured.out


def test_pyisolate_unknown_command_exits_nonzero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["doctro"])

    assert excinfo.value.code != 0
    captured = capsys.readouterr()
    assert "invalid choice" in captured.err
    assert "doctro" in captured.err
