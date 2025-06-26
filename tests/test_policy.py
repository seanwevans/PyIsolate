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
    import pyisolate as iso
    iso.set_policy_token("tok")
    bad = tmp_path / "bad.yml"
    bad.write_text("invalid")
    with pytest.raises(ValueError):
        policy.refresh(str(bad), token="tok")


def test_refresh_bad_token(tmp_path):
    policy = load_policy(no_yaml=True)
    import pyisolate as iso
    iso.set_policy_token("tok")
    good = tmp_path / "p.yml"
    good.write_text("version: 0.1\n")
    with pytest.raises(iso.PolicyAuthError):
        policy.refresh(str(good), token="wrong")


def test_list_parsing_without_pyyaml():
    policy = load_policy(no_yaml=True)
    doc = 'net:\n  - connect: "127.0.0.1:6379"'
    result = policy.yaml.safe_load(doc)
    assert result == {"net": [{"connect": "127.0.0.1:6379"}]}



def test_compile_policy_detects_conflict(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "sandboxes:\n"
        "  sb:\n"
        "    fs:\n"
        "      - allow: \"/tmp/data\"\n"
        "      - deny: \"/tmp/data\"\n"
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    with pytest.raises(policy.PolicyCompilerError):
        policy.compile_policy(str(f))


def test_compile_policy_ok(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "sandboxes:\n"
        "  sb:\n"
        "    fs:\n"
        "      - allow: \"/tmp/data\"\n"
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    assert compiled.sandboxes["sb"].fs[0].path == "/tmp/data"


def test_validation_missing_version(tmp_path):
    policy = load_policy(no_yaml=True)
    p = tmp_path / "p.yml"
    p.write_text("defaults: {}\n")
    with pytest.raises(ValueError, match="version"):
        policy.refresh(str(p), token="tok")


def test_validation_bad_section_type(tmp_path):
    policy = load_policy(no_yaml=True)
    p = tmp_path / "p.yml"
    p.write_text("version: 0.1\nsandboxes: []\n")
    with pytest.raises(ValueError, match="sandboxes"):
        policy.refresh(str(p), token="tok")

@pytest.mark.parametrize("name", ["ml.yml", "web_scraper.yml"])
def test_templates_parse(monkeypatch, name):
    policy = load_policy()
    monkeypatch.setattr(
        "pyisolate.bpf.manager.BPFManager.hot_reload", lambda *a, **k: None
    )
    path = ROOT / "policy" / name
    policy.refresh(str(path), token="tok")


