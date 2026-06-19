"""Canonical runtime policy model.

The compiler keeps its historical dataclasses for compatibility with callers that
consume ``CompiledPolicy`` directly.  This module defines the single structured
representation used at enforcement boundaries: sandbox threads and BPF map
updates both normalize inputs into :class:`RuntimePolicySet` first.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class FilesystemRule:
    """A canonical filesystem rule for one sandbox.

    ``access`` is meaningful for allow rules: ``read`` permits only non-writing
    opens, ``write`` permits only writing opens, and ``readwrite`` permits both.
    Legacy ``allow`` and ``deny`` rules default to ``readwrite`` so existing
    policies keep their previous behavior.
    """

    action: str
    path: str
    access: str = "readwrite"

    def __post_init__(self) -> None:
        action = self.action
        access = self.access
        if action in {"read", "write"}:
            access = action
            action = "allow"
            object.__setattr__(self, "action", action)
            object.__setattr__(self, "access", access)
        if action not in {"allow", "deny"}:
            raise ValueError(f"invalid filesystem action: {self.action}")
        if access not in {"read", "write", "readwrite"}:
            raise ValueError(f"invalid filesystem access mode: {self.access}")
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("filesystem rule path must be a non-empty string")


@dataclass(frozen=True)
class NetworkRule:
    """A canonical TCP destination rule for one sandbox."""

    action: str
    destination: str

    def __post_init__(self) -> None:
        if self.action not in {"connect", "deny"}:
            raise ValueError(f"invalid network action: {self.action}")
        if not isinstance(self.destination, str) or not self.destination:
            raise ValueError("network rule destination must be a non-empty string")


@dataclass(frozen=True)
class RuntimePolicy:
    """Canonical policy consumed by a sandbox runtime.

    Rules are split by behavior so the runtime can apply deny-before-allow
    semantics explicitly instead of inferring behavior from loosely shaped lists.
    Explicit runtime deny rules override all allow sources, including runtime
    allow rules, legacy allow lists, capabilities, and AuthoritySet grants.
    """

    allow_fs: tuple[FilesystemRule, ...] = ()
    deny_fs: tuple[FilesystemRule, ...] = ()
    allow_tcp: tuple[NetworkRule, ...] = ()
    deny_tcp: tuple[NetworkRule, ...] = ()
    imports: tuple[str, ...] = ()
    cpu_ms: int | None = None

    @property
    def fs(self) -> list[str]:
        """Legacy allow-list view used by older callers."""

        return [rule.path for rule in self.allow_fs]

    @property
    def tcp(self) -> list[str]:
        """Legacy connect-list view used by older callers."""

        return [rule.destination for rule in self.allow_tcp]

    @property
    def network_destinations(self) -> tuple[str, ...]:
        return tuple(rule.destination for rule in self.allow_tcp)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "allow_fs": [asdict(rule) for rule in self.allow_fs],
            "deny_fs": [asdict(rule) for rule in self.deny_fs],
            "allow_tcp": [asdict(rule) for rule in self.allow_tcp],
            "deny_tcp": [asdict(rule) for rule in self.deny_tcp],
            "imports": list(self.imports),
        }
        if self.cpu_ms is not None:
            data["cpu_ms"] = self.cpu_ms
        return data


@dataclass(frozen=True)
class RuntimePolicySet:
    """Canonical collection of runtime policies keyed by sandbox name."""

    schema_version: str = "1.0"
    semantics_version: int = 1
    sandboxes: Mapping[str, RuntimePolicy] = field(default_factory=dict)
    deny_log: tuple[str, ...] = ()

    def sandbox(self, name: str = "default") -> RuntimePolicy:
        if name in self.sandboxes:
            return self.sandboxes[name]
        if "default" in self.sandboxes:
            return self.sandboxes["default"]
        raise KeyError(f"unknown sandbox policy: {name}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "semantics_version": self.semantics_version,
            "sandboxes": {
                name: policy.to_dict() for name, policy in self.sandboxes.items()
            },
            "deny_log": list(self.deny_log),
        }


def _coerce_compiled_fs(rule: Any) -> FilesystemRule:
    action = getattr(rule, "action", None)
    path = getattr(rule, "path", None)
    access = getattr(rule, "access", "readwrite")
    if isinstance(rule, Mapping):
        action = rule.get("action")
        path = rule.get("path")
        access = rule.get("access", access)
    if action in {"read", "write"}:
        access = action
        action = "allow"
    return FilesystemRule(action=str(action), path=str(path), access=str(access))


def _coerce_compiled_tcp(rule: Any) -> NetworkRule:
    action = getattr(rule, "action", None)
    destination = getattr(rule, "addr", None)
    if isinstance(rule, Mapping):
        action = rule.get("action")
        destination = rule.get("addr", rule.get("destination"))
    return NetworkRule(action=str(action), destination=str(destination))


def from_sandbox_policy(policy: Any) -> RuntimePolicy:
    """Convert a legacy ``Policy`` or compiler ``SandboxPolicy`` into runtime form."""

    if isinstance(policy, RuntimePolicy):
        return policy

    allow_fs: list[FilesystemRule] = []
    deny_fs: list[FilesystemRule] = []
    allow_tcp: list[NetworkRule] = []
    deny_tcp: list[NetworkRule] = []

    fs_rules = getattr(policy, "fs", None) or []
    for item in fs_rules:
        if isinstance(item, str):
            allow_fs.append(FilesystemRule("allow", item))
            continue
        rule = _coerce_compiled_fs(item)
        if rule.action == "deny":
            deny_fs.append(rule)
        else:
            # ``_coerce_compiled_fs`` already normalized read/write rules into an
            # ``allow`` action carrying the correct ``access`` mode; preserve it
            # instead of collapsing every allow rule back to ``readwrite``.
            allow_fs.append(rule)

    tcp_rules = getattr(policy, "tcp", None) or []
    for item in tcp_rules:
        if isinstance(item, str):
            allow_tcp.append(NetworkRule("connect", item))
            continue
        rule = _coerce_compiled_tcp(item)
        if rule.action == "connect":
            allow_tcp.append(rule)
        else:
            deny_tcp.append(rule)

    imports = tuple(str(module) for module in (getattr(policy, "imports", None) or ()))
    return RuntimePolicy(
        allow_fs=tuple(allow_fs),
        deny_fs=tuple(deny_fs),
        allow_tcp=tuple(allow_tcp),
        deny_tcp=tuple(deny_tcp),
        imports=imports,
        cpu_ms=getattr(policy, "cpu_ms", None),
    )


def from_compiled_policy(compiled: Any) -> RuntimePolicySet:
    """Convert ``CompiledPolicy`` or its JSON/dict representation."""

    if isinstance(compiled, RuntimePolicySet):
        return compiled

    schema_version = str(
        getattr(compiled, "schema_version", None)
        or (compiled.get("schema_version") if isinstance(compiled, Mapping) else None)
        or "1.0"
    )
    semantics_version = int(
        getattr(compiled, "semantics_version", None)
        or (
            compiled.get("semantics_version") if isinstance(compiled, Mapping) else None
        )
        or 1
    )
    deny_log_raw = getattr(compiled, "deny_log", None)
    sandboxes_raw = getattr(compiled, "sandboxes", None)
    if isinstance(compiled, Mapping):
        deny_log_raw = compiled.get("deny_log", deny_log_raw)
        sandboxes_raw = compiled.get("sandboxes", sandboxes_raw)

    if not isinstance(sandboxes_raw, Mapping):
        raise ValueError("compiled policy must contain a sandboxes mapping")

    sandboxes: dict[str, RuntimePolicy] = {}
    for name, policy in sandboxes_raw.items():
        if isinstance(policy, Mapping) and {
            "allow_fs",
            "deny_fs",
            "allow_tcp",
            "deny_tcp",
        }.intersection(policy.keys()):
            sandboxes[str(name)] = RuntimePolicy(
                allow_fs=tuple(
                    FilesystemRule(**rule) for rule in policy.get("allow_fs", [])
                ),
                deny_fs=tuple(
                    FilesystemRule(**rule) for rule in policy.get("deny_fs", [])
                ),
                allow_tcp=tuple(
                    NetworkRule(**rule) for rule in policy.get("allow_tcp", [])
                ),
                deny_tcp=tuple(
                    NetworkRule(**rule) for rule in policy.get("deny_tcp", [])
                ),
                imports=tuple(str(module) for module in policy.get("imports", [])),
                cpu_ms=policy.get("cpu_ms"),
            )
        else:
            sandboxes[str(name)] = from_sandbox_policy(policy)

    return RuntimePolicySet(
        schema_version=schema_version,
        semantics_version=semantics_version,
        sandboxes=sandboxes,
        deny_log=tuple(str(item) for item in (deny_log_raw or ())),
    )


def from_yaml_dict(data: Mapping[str, Any]) -> RuntimePolicySet:
    """Compile a YAML dictionary into the canonical runtime policy set."""

    import tempfile

    from .compiler import compile_policy

    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:  # pragma: no cover - package fallback
        from . import yaml  # type: ignore[attr-defined]

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml") as tmp:
        if hasattr(yaml, "safe_dump"):
            yaml.safe_dump(dict(data), tmp)
        else:  # pragma: no cover - only used with the minimal fallback parser
            tmp.write(str(dict(data)))
        tmp_path = tmp.name
    try:
        return from_compiled_policy(compile_policy(tmp_path))
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def to_bpf_map_entries(policy_set: RuntimePolicySet) -> list[tuple[str, str, str]]:
    """Translate canonical policies to concrete BPF map update entries.

    Each returned tuple is ``(map_name, key, value)``.  The string values are the
    stable user-space encoding passed to ``bpftool`` by the placeholder manager.
    """

    entries: list[tuple[str, str, str]] = []
    for sandbox_name in sorted(policy_set.sandboxes):
        policy = policy_set.sandboxes[sandbox_name]
        for index, rule in enumerate(policy.allow_fs):
            entries.append(("policy_fs_allow", f"{sandbox_name}:{index}", rule.path))
        for index, rule in enumerate(policy.deny_fs):
            entries.append(("policy_fs_deny", f"{sandbox_name}:{index}", rule.path))
        for index, rule in enumerate(policy.allow_tcp):
            entries.append(
                ("policy_net_allow", f"{sandbox_name}:{index}", rule.destination)
            )
        for index, rule in enumerate(policy.deny_tcp):
            entries.append(
                ("policy_net_deny", f"{sandbox_name}:{index}", rule.destination)
            )
        for index, module in enumerate(policy.imports):
            entries.append(("policy_import_allow", f"{sandbox_name}:{index}", module))
    return entries


__all__ = [
    "FilesystemRule",
    "NetworkRule",
    "RuntimePolicy",
    "RuntimePolicySet",
    "from_compiled_policy",
    "from_sandbox_policy",
    "from_yaml_dict",
    "to_bpf_map_entries",
]
