import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

import pyisolate as iso
from pyisolate.capabilities import ROOT, RootCapability
from pyisolate.bpf.manager import BPFManager


def test_root_cap_type() -> None:
    assert isinstance(ROOT, RootCapability)


def test_reload_with_cap(monkeypatch, tmp_path) -> None:
    called = {}

    def fake_hot_reload(self, path):
        called["path"] = path

    monkeypatch.setattr(BPFManager, "hot_reload", fake_hot_reload)
    p = tmp_path / "p.json"
    p.write_text("{}")
    iso.reload_policy(str(p), ROOT)
    assert called["path"] == str(p)


def test_shutdown_with_cap() -> None:
    sup = iso.Supervisor()
    sb = sup.spawn("cap")
    sup.shutdown(ROOT)
    assert not sb._thread.is_alive()
