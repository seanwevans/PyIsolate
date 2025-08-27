import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate.cgroup as cgroup


def test_write_logs_warning_on_error(tmp_path, caplog):
    file = tmp_path / "missing" / "cpu.max"
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup._write(file, "1")
    assert "Failed to write" in caplog.text


def test_create_logs_warning_on_error(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(cgroup, "_BASE", tmp_path)

    def failing_mkdir(self, parents=True, exist_ok=True):
        raise PermissionError("boom")

    monkeypatch.setattr(Path, "mkdir", failing_mkdir)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        assert cgroup.create("cg") is None
    assert "Failed to create cgroup" in caplog.text


def test_attach_logs_warning_on_error(tmp_path, monkeypatch, caplog):
    path = tmp_path

    def failing_write(self, data):
        raise OSError("boom")

    monkeypatch.setattr(Path, "write_text", failing_write)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup.attach_current(path)
    assert "Failed to attach thread" in caplog.text


def test_delete_logs_warning_on_error(tmp_path, monkeypatch, caplog):
    path = tmp_path / "cg"
    path.mkdir()

    def failing_rmdir(self):
        raise OSError("boom")

    monkeypatch.setattr(Path, "rmdir", failing_rmdir)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup.delete(path)
    assert "Failed to delete cgroup" in caplog.text
