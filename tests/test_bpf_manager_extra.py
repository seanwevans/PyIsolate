import pytest

from pyisolate.bpf.manager import BPFManager


def test_hot_reload_requires_load(tmp_path):
    mgr = BPFManager()
    policy = tmp_path / "p.json"
    policy.write_text("{}")
    with pytest.raises(RuntimeError):
        mgr.hot_reload(str(policy))


def test_hot_reload_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: None)
    mgr = BPFManager()
    mgr.load()
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid}")
    with pytest.raises(RuntimeError):
        mgr.hot_reload(str(bad))


def test_hot_reload_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **k: None)
    mgr = BPFManager()
    mgr.load()
    missing = tmp_path / "missing.json"
    with pytest.raises(RuntimeError):
        mgr.hot_reload(str(missing))
