import json
import random
import string
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate.policy as policy
from pyisolate.bpf.manager import BPFManager


def random_text(max_len=20):
    letters = string.ascii_letters + string.digits + "\n: -"
    return "".join(random.choice(letters) for _ in range(random.randint(1, max_len)))


def test_policy_parser_fuzz():
    for _ in range(100):
        data = random_text()
        try:
            policy.yaml.safe_load(data)
        except Exception:
            pass


def test_bpf_hot_reload_fuzz(tmp_path, monkeypatch):
    monkeypatch.setattr(BPFManager, "_run", lambda *a, **k: True)
    mgr = BPFManager()
    mgr.load()

    for _ in range(50):
        mapping = {random_text(5): random_text(5) for _ in range(3)}
        p = tmp_path / "p.json"
        p.write_text(json.dumps(mapping))
        mgr.hot_reload(str(p))

        p.write_text(random_text())
        with pytest.raises((RuntimeError, AttributeError)):
            mgr.hot_reload(str(p))
