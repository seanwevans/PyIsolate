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
        # A structurally valid canonical policy must hot-reload cleanly.
        valid_policy = {
            "schema_version": "1.0",
            "semantics_version": 1,
            "sandboxes": {
                "default": {
                    "allow_fs": [
                        {
                            "action": "allow",
                            "path": "/" + random_text(5),
                            "access": "readwrite",
                        }
                    ],
                    "deny_fs": [],
                    "allow_tcp": [],
                    "deny_tcp": [],
                    "imports": ["math"],
                }
            },
            "deny_log": [],
        }
        p = tmp_path / "p.json"
        p.write_text(json.dumps(valid_policy))
        mgr.hot_reload(str(p))

        # Random, structurally invalid payloads must be rejected, not crash.
        p.write_text(random_text())
        with pytest.raises((RuntimeError, AttributeError)):
            mgr.hot_reload(str(p))
