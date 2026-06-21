import errno
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

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
        status = cgroup.create("cg")
    assert status.path is None
    assert not status.enforced
    assert status.errors
    assert "Failed to create cgroup" in caplog.text


def test_create_fails_closed_in_hardened_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(cgroup, "_BASE", tmp_path)

    def failing_mkdir(self, parents=True, exist_ok=True):
        raise PermissionError("boom")

    monkeypatch.setattr(Path, "mkdir", failing_mkdir)
    with pytest.raises(RuntimeError):
        cgroup.create("cg", mode="hardened")


def test_attach_logs_warning_on_error(tmp_path, monkeypatch, caplog):
    path = tmp_path

    def failing_write(self, data):
        raise OSError("boom")

    monkeypatch.setattr(Path, "write_text", failing_write)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup.attach_current(path)
    assert "Failed to attach thread" in caplog.text


def test_delete_does_not_unlink_files(tmp_path, monkeypatch):
    path = tmp_path / "cg"
    path.mkdir()
    (path / "some.file").write_text("x")

    def unlink_should_not_be_called(self, *args, **kwargs):  # pragma: no cover
        raise AssertionError("unlink() should not be used by delete()")

    monkeypatch.setattr(Path, "unlink", unlink_should_not_be_called)
    cgroup.delete(path)
    assert path.exists()


def test_delete_drains_all_threads_despite_failures(tmp_path, monkeypatch):
    path = tmp_path / "cg"
    path.mkdir()
    (path / "cgroup.threads").write_text("100\n200\n300\n")
    parent_threads = tmp_path / "cgroup.threads"

    attempted = []
    real_write_text = Path.write_text

    def tracking_write_text(self, data, *args, **kwargs):
        if self == parent_threads:
            attempted.append(data)
            if data == "100":
                raise OSError(errno.ESRCH, "No such process")
            return None
        return real_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", tracking_write_text)
    cgroup.delete(path)
    # A failed migration for one TID (e.g. an exited thread) must not abandon
    # draining the remaining threads.
    assert attempted == ["100", "200", "300"]


def test_delete_logs_busy_warning(tmp_path, monkeypatch, caplog):
    path = tmp_path / "cg"
    path.mkdir()

    def failing_rmdir(self):
        raise OSError(errno.ENOTEMPTY, "Directory not empty")

    monkeypatch.setattr(Path, "rmdir", failing_rmdir)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup.delete(path)
    assert "busy/non-empty" in caplog.text


def test_delete_logs_permission_error(tmp_path, monkeypatch, caplog):
    path = tmp_path / "cg"
    path.mkdir()

    def failing_rmdir(self):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "rmdir", failing_rmdir)
    with caplog.at_level(logging.WARNING, logger=cgroup.__name__):
        cgroup.delete(path)
    assert "Permission denied deleting cgroup" in caplog.text


def test_list_children_and_cleanup_orphans(tmp_path, monkeypatch):
    monkeypatch.setattr(cgroup, "_BASE", tmp_path / "pyisolate")
    keep = cgroup.create("keep")
    orphan = cgroup.create("orphan")

    children = {p.name for p in cgroup.list_children()}
    assert {"keep", "orphan"}.issubset(children)

    removed = cgroup.cleanup_orphans({"keep"})
    assert {p.name for p in removed} == {"orphan"}
    assert keep is not None and keep.exists()
    assert orphan is not None and not orphan.exists()


def test_create_reports_controller_enforcement(tmp_path, monkeypatch):
    monkeypatch.setattr(cgroup, "_BASE", tmp_path / "pyisolate")

    status = cgroup.create("limited", cpu_ms=5, mem_bytes=4096)

    assert status.path == tmp_path / "pyisolate" / "limited"
    assert status.cpu is True
    assert status.memory is True
    assert status.enforced is True
    assert status.errors == ()


@pytest.mark.parametrize("bad", ["../escaped", "a/b", "..", ".", "", "a/../b"])
def test_create_rejects_unsafe_names(monkeypatch, tmp_path, bad):
    monkeypatch.setattr(cgroup, "_BASE", tmp_path)
    with pytest.raises(ValueError):
        cgroup.create(bad)
    # Rejected before any mkdir, so nothing is created inside or outside _BASE.
    assert list(tmp_path.iterdir()) == []
