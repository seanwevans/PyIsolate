import sys
from pathlib import Path
import importlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest


def load_policy(no_yaml: bool = False):
    if no_yaml:
        sys.modules.pop("yaml", None)
    if "pyisolate.policy" in sys.modules:
        del sys.modules["pyisolate.policy"]
    return importlib.import_module("pyisolate.policy")


def test_policy_methods_chain():
    policy = load_policy(no_yaml=True)
    p = policy.Policy()
    assert p.allow_fs("/tmp") is p
    assert p.allow_tcp("127.0.0.1") is p
    assert p.fs == ["/tmp"]
    assert p.tcp == ["127.0.0.1"]


def test_policy_refresh_invalid(tmp_path):
    policy = load_policy(no_yaml=True)
    bad = tmp_path / "bad.yml"
    bad.write_text("invalid")
    with pytest.raises(ValueError):
        policy.refresh(str(bad))


def test_list_parsing_without_pyyaml():
    policy = load_policy(no_yaml=True)
    doc = 'net:\n  - connect: "127.0.0.1:6379"'
    result = policy.yaml.safe_load(doc)
    assert result == {"net": [{"connect": "127.0.0.1:6379"}]}
