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


@pytest.mark.parametrize(
    ("doc", "msg"),
    [
        ("defaults: {}\n", "version"),
        ("version: 9\n", "unsupported policy version"),
        ("version: 0.1\nsandboxes: []\n", "sandboxes"),
    ],
)
def test_refresh_validation_fails_before_compile_or_reload(
    monkeypatch, tmp_path, doc, msg
):
    policy = load_policy(no_yaml=True)
    import pyisolate as iso

    iso.set_policy_token("tok")
    path = tmp_path / "bad.yml"
    path.write_text(doc)

    compile_calls = 0
    reload_calls = 0

    def fake_compile(_path):
        nonlocal compile_calls
        compile_calls += 1
        raise AssertionError("compile_policy must not run for invalid schema/version")

    def fake_reload(*_args, **_kwargs):
        nonlocal reload_calls
        reload_calls += 1
        raise AssertionError("reload_policy must not run for invalid schema/version")

    monkeypatch.setattr(policy, "compile_policy", fake_compile)
    monkeypatch.setattr("pyisolate.supervisor.reload_policy", fake_reload)

    with pytest.raises(ValueError, match=msg):
        policy.refresh(str(path), token="tok")

    assert compile_calls == 0
    assert reload_calls == 0


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
    assert sb["allow_tcp"][0]["destination"] == "1.1.1.1:443"
    assert sb["imports"] == ["math"]
    assert sb["allow_fs"][0]["path"] == "/tmp/**"
    assert captured["data"]["schema_version"] == "0.1"
    assert captured["data"]["semantics_version"] == 1


def test_refresh_dry_run_compiles_without_reload(monkeypatch, tmp_path):
    policy = load_policy()
    import pyisolate as iso

    called = False

    def fake_reload(*_args, **_kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("pyisolate.supervisor.reload_policy", fake_reload)
    iso.set_policy_token("tok")
    path = tmp_path / "p.yml"
    path.write_text(
        "version: 1\n" "sandboxes:\n" "  sb:\n" "    fs:\n" '      - allow: "/tmp"\n'
    )

    compiled = policy.refresh(str(path), token="tok", dry_run=True)
    assert compiled.schema_version == "1.0"
    assert called is False


def test_compile_policy_supports_inheritance_and_defaults(tmp_path):
    import pyisolate.policy as policy

    doc = (
        "version: 1.0\n"
        "defaults:\n"
        "  imports:\n"
        "    - math\n"
        "sandboxes:\n"
        "  base:\n"
        "    fs:\n"
        '      - allow: "/srv/base"\n'
        "    net:\n"
        '      - deny: "10.0.0.0/8"\n'
        "  child:\n"
        "    extends: base\n"
        "    imports:\n"
        "      - json\n"
        "    fs:\n"
        '      - allow: "/srv/child"\n'
    )
    f = tmp_path / "inherit.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    child = compiled.sandboxes["child"]
    assert [r.path for r in child.fs] == ["/srv/base", "/srv/child"]
    assert [r.addr for r in child.tcp] == ["10.0.0.0/8"]
    assert child.imports == ["math", "json"]
    assert compiled.deny_log == [
        "sandbox=base net=10.0.0.0/8",
        "sandbox=child net=10.0.0.0/8",
    ]


def test_refresh_logs_explicit_deny_rules(tmp_path, caplog, monkeypatch):
    policy = load_policy()
    import pyisolate as iso

    monkeypatch.setattr(
        "pyisolate.bpf.manager.BPFManager.hot_reload", lambda *a, **k: None
    )
    iso.set_policy_token("tok")
    path = tmp_path / "deny.yml"
    path.write_text("version: 0.1\n" "net:\n" '  - deny: "10.0.0.0/8"\n')
    with caplog.at_level("WARNING"):
        policy.refresh(str(path), token="tok")
    assert "policy deny rule active" in caplog.text


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


def test_resolve_unknown_policy_fails_closed():
    import pyisolate.policy as policy

    with pytest.raises(policy.PolicyCompilerError, match="unknown policy"):
        policy.resolve_policy("does-not-exist")


def test_named_policy_applies_runtime_restrictions(tmp_path):
    import pyisolate as iso

    allowed = tmp_path / "allowed.txt"
    allowed.write_text("ok")

    sb = iso.spawn("named-policy", policy="stdlib.readonly")
    try:
        sb.exec("import math; post(math.sqrt(25))")
        assert sb.recv(timeout=1) == 5.0

        sb.exec("import random")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec(f"post(open({str(allowed)!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec("post(open('/etc/hosts').read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec(
            "import socket\n"
            "s = socket.socket()\n"
            "try:\n"
            "    s.connect(('127.0.0.1', 9))\n"
            "finally:\n"
            "    s.close()\n"
        )
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_compile_policy_emits_first_class_capabilities(tmp_path):
    import pyisolate.policy as policy
    from pyisolate.capabilities import (
        ConnectTCP,
        CpuBudget,
        Import,
        ReadPath,
        WritePath,
    )

    doc = (
        "version: 1.0\n"
        "sandboxes:\n"
        "  sb:\n"
        "    fs:\n"
        '      - read: "/tmp/input"\n'
        '      - write: "/tmp/output"\n'
        "    net:\n"
        '      - connect: "api.example.com:443"\n'
        "    imports: [math]\n"
        "    cpu_ms: 50\n"
    )
    f = tmp_path / "p.yml"
    f.write_text(doc)

    compiled = policy.compile_policy(str(f))
    caps = compiled.sandboxes["sb"].capabilities
    assert any(
        isinstance(cap, ReadPath) and str(cap.path) == "/tmp/input" for cap in caps
    )
    assert any(
        isinstance(cap, WritePath) and str(cap.path) == "/tmp/output" for cap in caps
    )
    assert any(
        isinstance(cap, ConnectTCP) and cap.address == "api.example.com:443"
        for cap in caps
    )
    assert any(isinstance(cap, Import) and cap.module == "math" for cap in caps)
    assert any(isinstance(cap, CpuBudget) and cap.ms == 50 for cap in caps)
    assert compiled.sandboxes["sb"].cpu_ms == 50


def test_policy_objects_serialize_to_yaml_shape():
    import pyisolate as iso
    from pyisolate import policy

    p = policy.Policy().grant(
        iso.ReadPath("/tmp/input"),
        iso.WritePath("/tmp/output"),
        iso.ConnectTCP("api.example.com", 443),
        iso.Import("math"),
        iso.CpuBudget(50),
    )

    assert p.to_dict("job") == {
        "version": "1.0",
        "sandboxes": {
            "job": {
                "fs": [{"read": "/tmp/input"}, {"write": "/tmp/output"}],
                "net": [{"connect": "api.example.com:443"}],
                "imports": ["math"],
                "cpu_ms": 50,
            }
        },
    }


def test_policy_objects_serialize_to_yaml_without_pyyaml(monkeypatch):
    import pyisolate as iso
    from pyisolate import policy

    p = policy.Policy().grant(
        iso.ReadPath("/tmp/input"),
        iso.WritePath("/tmp/output"),
        iso.ConnectTCP("api.example.com", 443),
        iso.Import("math"),
        iso.CpuBudget(50),
    )

    monkeypatch.setattr(policy, "yaml", object())

    assert p.to_yaml("job") == (
        "version: 1.0\n"
        "sandboxes:\n"
        "  job:\n"
        "    fs:\n"
        "      - read: '/tmp/input'\n"
        "      - write: '/tmp/output'\n"
        "    net:\n"
        "      - connect: 'api.example.com:443'\n"
        "    imports:\n"
        "      - math\n"
        "    cpu_ms: 50\n"
    )


def test_canonical_yaml_policy_drives_sandbox_and_bpf_maps(tmp_path, monkeypatch):
    import pyisolate as iso
    import pyisolate.policy as policy
    from pyisolate.bpf.manager import (
        BPF_KEY_BYTES,
        BPF_VALUE_BYTES,
        BPFManager,
        encode_map_field,
    )
    from pyisolate.policy import from_compiled_policy

    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    allowed_file = allowed_dir / "data.txt"
    allowed_file.write_text("ok")
    blocked_file = tmp_path / "blocked.txt"
    blocked_file.write_text("nope")

    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "version: 1.0\n"
        "sandboxes:\n"
        "  default:\n"
        "    imports:\n"
        "      - pathlib\n"
        "    fs:\n"
        f'      - allow: "{allowed_dir}/**"\n'
        f'      - deny: "{blocked_file}"\n'
        "    net:\n"
        '      - connect: "127.0.0.1:9"\n'
        '      - deny: "127.0.0.1:10"\n'
    )

    runtime_policies = from_compiled_policy(policy.compile_policy(str(policy_path)))
    runtime_policy = runtime_policies.sandbox("default")

    sb = iso.spawn("canonical-policy", policy=runtime_policy)
    try:
        sb.exec(
            "import pathlib\n"
            f"post(pathlib.Path({str(allowed_file)!r}).read_text())\n"
        )
        assert sb.recv(timeout=1) == "ok"

        sb.exec(
            "import pathlib\n"
            f"post(pathlib.Path({str(blocked_file)!r}).read_text())\n"
        )
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec("import math")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    calls = []

    def record(self, cmd, *, raise_on_error=False):
        calls.append(cmd)
        return True

    monkeypatch.setattr(BPFManager, "_run", record)
    mgr = BPFManager()
    mgr.loaded = True
    canonical_path = tmp_path / "policy.json"
    canonical_path.write_text(json.dumps(runtime_policies.to_dict()))

    mgr.hot_reload(str(canonical_path))

    assert mgr.policy_maps == runtime_policies.to_dict()
    assert [
        "bpftool",
        "map",
        "update",
        "pinned",
        "/sys/fs/bpf/policy_fs_allow",
        "key",
        *encode_map_field("default:0", BPF_KEY_BYTES),
        "value",
        *encode_map_field(f"{allowed_dir}/**", BPF_VALUE_BYTES),
        "any",
    ] in calls
    assert [
        "bpftool",
        "map",
        "update",
        "pinned",
        "/sys/fs/bpf/policy_net_allow",
        "key",
        *encode_map_field("default:0", BPF_KEY_BYTES),
        "value",
        *encode_map_field("127.0.0.1:9", BPF_VALUE_BYTES),
        "any",
    ] in calls


@pytest.mark.parametrize("cpu_ms", [0, -1, True, False, 1.5, "100"])
def test_from_compiled_policy_rejects_invalid_canonical_cpu_ms(cpu_ms):
    from pyisolate.policy import from_compiled_policy

    with pytest.raises(ValueError, match="cpu_ms"):
        from_compiled_policy(
            {
                "schema_version": "1.0",
                "semantics_version": 1,
                "sandboxes": {"default": {"imports": [], "cpu_ms": cpu_ms}},
            }
        )


@pytest.mark.parametrize("imports", [[123], [""], [None], "math"])
def test_from_compiled_policy_rejects_invalid_canonical_imports(imports):
    from pyisolate.policy import from_compiled_policy

    with pytest.raises(ValueError, match="imports"):
        from_compiled_policy(
            {
                "schema_version": "1.0",
                "semantics_version": 1,
                "sandboxes": {"default": {"imports": imports}},
            }
        )


@pytest.mark.parametrize(
    ("rule_field", "rules"),
    [
        ("allow_fs", ["not-a-mapping"]),
        ("deny_fs", [None]),
        ("allow_tcp", ["not-a-mapping"]),
        ("deny_tcp", [None]),
        ("allow_fs", {"action": "allow", "path": "/tmp"}),
    ],
)
def test_from_compiled_policy_rejects_non_mapping_canonical_rule_entries(
    rule_field, rules
):
    from pyisolate.policy import from_compiled_policy

    with pytest.raises(ValueError, match=rule_field):
        from_compiled_policy(
            {
                "schema_version": "1.0",
                "semantics_version": 1,
                "sandboxes": {"default": {rule_field: rules}},
            }
        )


def test_resolve_policy_path_preserves_deny_and_cpu_ms(tmp_path):
    import pyisolate.policy as policy

    allowed = tmp_path / "allowed"
    denied = tmp_path / "allowed" / "secret.txt"
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "version: 1.0\n"
        "sandboxes:\n"
        "  default:\n"
        "    fs:\n"
        f'      - allow: "{allowed}/**"\n'
        f'      - deny: "{denied}"\n'
        "    cpu_ms: 25\n"
    )

    resolved = policy.resolve_policy(str(policy_path))

    assert resolved.cpu_ms == 25
    assert [rule.path for rule in resolved.allow_fs] == [f"{allowed}/**"]
    assert [rule.path for rule in resolved.deny_fs] == [str(denied)]


def test_resolve_policy_dict_preserves_deny_and_cpu_ms(tmp_path):
    import pyisolate.policy as policy

    allowed = tmp_path / "allowed"
    denied = tmp_path / "allowed" / "secret.txt"
    resolved = policy.resolve_policy(
        {
            "version": "1.0",
            "sandboxes": {
                "default": {
                    "fs": [
                        {"allow": f"{allowed}/**"},
                        {"deny": str(denied)},
                    ],
                    "cpu_ms": 30,
                }
            },
        }
    )

    assert resolved.cpu_ms == 30
    assert [rule.path for rule in resolved.allow_fs] == [f"{allowed}/**"]
    assert [rule.path for rule in resolved.deny_fs] == [str(denied)]


def test_resolve_policy_path_deny_rule_remains_effective(tmp_path):
    import pytest

    import pyisolate as iso
    import pyisolate.policy as policy

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    denied = allowed / "secret.txt"
    denied.write_text("secret")
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(
        "version: 1.0\n"
        "sandboxes:\n"
        "  default:\n"
        "    imports:\n"
        "      - pathlib\n"
        "    fs:\n"
        f'      - allow: "{allowed}/**"\n'
        f'      - deny: "{denied}"\n'
        "    cpu_ms: 25\n"
    )

    sb = iso.spawn("resolved-deny", policy=policy.resolve_policy(str(policy_path)))
    try:
        sb.exec("import pathlib\n" f"post(pathlib.Path({str(denied)!r}).read_text())\n")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
        assert sb._thread.cpu_quota_ms == 25
    finally:
        sb.close()


@pytest.mark.parametrize(
    "bucket, rule",
    [
        ("allow_fs", {"action": "deny", "path": "/etc"}),
        ("allow_tcp", {"action": "deny", "destination": "10.0.0.1:22"}),
        ("deny_fs", {"action": "allow", "path": "/etc"}),
        ("deny_tcp", {"action": "connect", "destination": "10.0.0.1:22"}),
    ],
)
def test_canonical_policy_rejects_contradictory_action(bucket, rule):
    # Enforcement keys off the bucket, not the rule action, so a deny rule under
    # allow_fs/allow_tcp would otherwise be enforced as an allow (deny -> allow).
    # The canonical-mapping path must reject the contradiction. Reachable via the
    # public from_compiled_policy (checkpoint restore / BPF JSON policy).
    from pyisolate.policy.model import from_compiled_policy

    blob = {"sandboxes": {"s1": {bucket: [rule]}}}
    with pytest.raises(ValueError, match="only accepts"):
        from_compiled_policy(blob)


def test_canonical_policy_accepts_consistent_actions():
    # The well-formed counterpart of the rejection test still parses, including
    # the read/write -> allow access normalization.
    from pyisolate.policy.model import from_compiled_policy

    rendered = from_compiled_policy(
        {
            "sandboxes": {
                "s1": {
                    "allow_fs": [
                        {"action": "allow", "path": "/tmp"},
                        {"action": "read", "path": "/etc/hosts"},
                    ],
                    "deny_fs": [{"action": "deny", "path": "/secret"}],
                    "allow_tcp": [{"action": "connect", "destination": "1.2.3.4:80"}],
                    "deny_tcp": [{"action": "deny", "destination": "9.9.9.9:53"}],
                }
            }
        }
    )
    rp = rendered.sandboxes["s1"]
    assert [(r.action, r.access) for r in rp.allow_fs] == [
        ("allow", "readwrite"),
        ("allow", "read"),
    ]
    assert [r.action for r in rp.deny_fs] == ["deny"]
    assert [r.action for r in rp.allow_tcp] == ["connect"]
    assert [r.action for r in rp.deny_tcp] == ["deny"]


def test_from_yaml_dict_cleans_up_tempfile_on_dump_error(tmp_path, monkeypatch):
    # from_yaml_dict writes a delete=False temp file before compiling it. If the
    # YAML serialization raises, the file must still be removed rather than
    # leaked once per failure.
    import tempfile

    import yaml

    from pyisolate.policy.model import from_yaml_dict

    real_named_temp = tempfile.NamedTemporaryFile

    def named_temp_in_tmp_path(*args, **kwargs):
        kwargs.setdefault("dir", str(tmp_path))
        return real_named_temp(*args, **kwargs)

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", named_temp_in_tmp_path)

    def boom(*args, **kwargs):
        raise RuntimeError("dump failed")

    monkeypatch.setattr(yaml, "safe_dump", boom)

    with pytest.raises(RuntimeError, match="dump failed"):
        from_yaml_dict({"version": "1.0", "sandboxes": {}})

    assert list(tmp_path.iterdir()) == []
