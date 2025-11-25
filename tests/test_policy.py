import importlib
import json
import sys
from pathlib import Path

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
        '      - allow: "/tmp/data"\n'
        '      - deny: "/tmp/data"\n'
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    with pytest.raises(policy.PolicyCompilerError):
        policy.compile_policy(str(f))


def test_compile_policy_ok(tmp_path):
    import pyisolate.policy as policy

    doc = "sandboxes:\n" "  sb:\n" "    fs:\n" '      - allow: "/tmp/data"\n'
    f = tmp_path / "p.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    assert compiled.sandboxes["sb"].fs[0].path == "/tmp/data"


def test_compile_policy_net_and_imports(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "sandboxes:\n"
        "  sb:\n"
        "    net:\n"
        '      - connect: "127.0.0.1:6379"\n'
        '      - deny: "10.0.0.0/8"\n'
        "    imports:\n"
        "      - math\n"
        "      - json\n"
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    sandbox = compiled.sandboxes["sb"]
    assert [r.addr for r in sandbox.tcp] == [
        "127.0.0.1:6379",
        "10.0.0.0/8",
    ]
    assert [r.action for r in sandbox.tcp] == ["connect", "deny"]
    assert sandbox.imports == ["math", "json"]


def test_compile_tcp_accepts_address_list(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "version: 0.1\n"
        "sandboxes:\n"
        "  sb:\n"
        "    net:\n"
        '      - connect: ["127.0.0.1:6379", "10.0.0.1:53"]\n'
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    sandbox = compiled.sandboxes["sb"]

    assert [r.addr for r in sandbox.tcp] == ["127.0.0.1:6379", "10.0.0.1:53"]
    assert [r.action for r in sandbox.tcp] == ["connect", "connect"]


def test_compile_tcp_rejects_non_string_addresses(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "version: 0.1\n"
        "sandboxes:\n"
        "  sb:\n"
        "    net:\n"
        "      - connect: [123]\n"
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    with pytest.raises(policy.PolicyCompilerError, match="net addresses in 'sb'"):
        policy.compile_policy(str(f))


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
    compiled = policy.compile_policy(str(path))
    assert compiled.sandboxes
    import pyisolate as iso

    iso.set_policy_token("tok")
    policy.refresh(str(path), token="tok")


def test_refresh_passes_compiled_policy(monkeypatch, tmp_path):
    policy = load_policy()
    import pyisolate as iso

    captured: dict[str, dict] = {}

    def fake_hot_reload(self, policy_path):
        with open(policy_path, "r", encoding="utf-8") as fh:
            captured["data"] = json.load(fh)

    monkeypatch.setattr("pyisolate.bpf.manager.BPFManager.hot_reload", fake_hot_reload)
    iso.set_policy_token("tok")

    path = tmp_path / "p.yml"
    path.write_text(
        "version: 0.1\n"
        "net:\n"
        '  - connect: "1.1.1.1:443"\n'
        "imports:\n"
        "  - math\n"
        "fs:\n"
        '  - allow: "/tmp/**"\n'
    )

    policy.refresh(str(path), token="tok")

    sb = captured["data"]["sandboxes"]["default"]
    assert sb["tcp"][0]["addr"] == "1.1.1.1:443"
    assert sb["imports"] == ["math"]
    assert sb["fs"][0]["path"] == "/tmp/**"


def test_reload_policy_missing_path(tmp_path):
    import pyisolate as iso

    missing = tmp_path / "nope.json"
    with pytest.raises(FileNotFoundError):
        iso.reload_policy(str(missing))


def test_reload_policy_malformed_json(tmp_path):
    import pyisolate as iso

    bad = tmp_path / "bad.json"
    bad.write_text("not-json")
    with pytest.raises(iso.PolicyAuthError, match="failed to reload policy"):
        iso.reload_policy(str(bad))


def test_reload_policy_accepts_root_token(monkeypatch, tmp_path):
    import pyisolate as iso
    from pyisolate.capabilities import ROOT

    monkeypatch.setattr(
        "pyisolate.bpf.manager.BPFManager.hot_reload", lambda *a, **k: None
    )
    iso.set_policy_token("tok")
    path = tmp_path / "p.json"
    path.write_text("{}")

    iso.reload_policy(str(path), token=ROOT)


def test_reload_policy_rejects_non_canonical_root(monkeypatch, tmp_path, caplog):
    import pyisolate as iso
    from pyisolate.capabilities import RootCapability

    monkeypatch.setattr(
        "pyisolate.bpf.manager.BPFManager.hot_reload", lambda *a, **k: None
    )
    iso.set_policy_token("tok")
    path = tmp_path / "p.json"
    path.write_text("{}")

    fake = RootCapability(name="root")
    with caplog.at_level("WARNING"):
        with pytest.raises(iso.PolicyAuthError):
            iso.reload_policy(str(path), token=fake)
    assert "invalid token" in caplog.text
