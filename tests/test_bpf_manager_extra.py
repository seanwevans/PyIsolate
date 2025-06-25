import pytest
from pathlib import Path
from pyisolate.bpf.manager import BPFManager


def test_hot_reload_requires_load(tmp_path):
    mgr = BPFManager()
    policy = tmp_path / "p.json"
    policy.write_text("{}")
    with pytest.raises(RuntimeError):
        mgr.hot_reload(str(policy))
