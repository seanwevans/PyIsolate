"""Policy DSL compiler.

This module parses the YAML based policy DSL described in
``POLICY.md`` and converts it to a dictionary representation suitable
for feeding into the BPF manager.  It also validates the document and
catches conflicting rules such as an ``allow`` and ``deny`` for the
same path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List

try:
    import yaml  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - fallback already tested
    from . import yaml  # type: ignore  # type: ignore[attr-defined]


class PolicyCompilerError(ValueError):
    """Raised when the policy is malformed or contains conflicts."""


@dataclass
class FSRule:
    action: str
    path: str


@dataclass
class TCPRule:
    action: str
    addr: str


@dataclass
class SandboxPolicy:
    fs: List[FSRule]
    tcp: List[TCPRule]
    imports: List[str]


@dataclass
class CompiledPolicy:
    schema_version: str
    semantics_version: int
    sandboxes: Dict[str, SandboxPolicy]
    deny_log: List[str]


def _simple_parse(text: str) -> Dict[str, Any]:
    """Parse a minimal subset of the policy DSL without PyYAML."""

    data: Dict[str, Any] = {"sandboxes": {}}
    current_sb: str | None = None
    current_section: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        token = raw.strip()

        if indent == 0:
            if token == "sandboxes:":
                continue
            if ":" in token:
                # ignore other top-level keys like version
                continue
            raise PolicyCompilerError("invalid syntax")
        elif indent == 2 and token.endswith(":"):
            current_sb = token[:-1]
            data["sandboxes"][current_sb] = {}
        elif indent == 4 and token.endswith(":") and current_sb is not None:
            current_section = token[:-1]
            data["sandboxes"][current_sb][current_section] = []
        elif indent == 6 and token.startswith("- ") and current_sb and current_section:
            item = token[2:]
            if ":" in item:
                k, v = item.split(":", 1)
                v = v.strip().strip('"').strip("'")
                data["sandboxes"][current_sb][current_section].append({k.strip(): v})
            else:
                data["sandboxes"][current_sb][current_section].append(
                    item.strip().strip('"').strip("'")
                )
        else:
            # Ignore unrecognized lines for minimal templates
            continue
    return data


def _compile_fs(rules: List[dict], sb_name: str) -> List[FSRule]:
    compiled: List[FSRule] = []
    seen: Dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict) or len(rule) != 1:
            raise PolicyCompilerError(f"invalid fs rule in '{sb_name}': {rule}")
        action, path = next(iter(rule.items()))
        if action not in ("allow", "deny"):
            raise PolicyCompilerError(f"invalid fs action '{action}' in '{sb_name}'")
        if path in seen and seen[path] != action:
            raise PolicyCompilerError(
                f"conflicting fs rules for '{path}' in '{sb_name}'"
            )
        seen[path] = action
        compiled.append(FSRule(action=action, path=path))
    return compiled


def _compile_tcp(rules: List[dict], sb_name: str) -> List[TCPRule]:
    compiled: List[TCPRule] = []
    seen: Dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict) or len(rule) != 1:
            raise PolicyCompilerError(f"invalid net rule in '{sb_name}': {rule}")
        action, addr = next(iter(rule.items()))
        if action not in ("connect", "deny"):
            raise PolicyCompilerError(f"invalid net action '{action}' in '{sb_name}'")
        addresses = addr if isinstance(addr, list) else [addr]
        for address in addresses:
            if not isinstance(address, str):
                raise PolicyCompilerError(
                    f"net addresses in '{sb_name}' must be strings: {address!r}"
                )
            if address in seen and seen[address] != action:
                raise PolicyCompilerError(
                    f"conflicting net rules for '{address}' in '{sb_name}'"
                )
            seen[address] = action
            compiled.append(TCPRule(action=action, addr=address))
    return compiled


def _norm_rule_list(value: object, *, field_name: str, sb_name: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PolicyCompilerError(f"'{field_name}' in '{sb_name}' must be a list")
    return value


def _merge_unique(parent: list, child: list) -> list:
    merged = list(parent)
    for item in child:
        if item not in merged:
            merged.append(item)
    return merged


def _resolve_sandbox(
    name: str, raw_boxes: dict[str, dict[str, Any]], defaults: dict[str, Any]
) -> dict[str, Any]:
    resolved: dict[str, dict[str, Any]] = {}
    resolving: set[str] = set()

    def _resolve(current: str) -> dict[str, Any]:
        if current in resolved:
            return resolved[current]
        if current in resolving:
            raise PolicyCompilerError(f"cyclic inheritance detected at '{current}'")
        if current not in raw_boxes:
            raise PolicyCompilerError(f"unknown parent sandbox '{current}'")
        resolving.add(current)
        cfg = raw_boxes[current]
        parent_name = cfg.get("extends")
        parent_cfg: dict[str, Any] = {}
        if parent_name is not None:
            if not isinstance(parent_name, str):
                raise PolicyCompilerError(f"'extends' in '{current}' must be a string")
            parent_cfg = _resolve(parent_name)
        base = {
            "fs": _merge_unique(
                _norm_rule_list(defaults.get("fs", []), field_name="fs", sb_name=current),
                _norm_rule_list(parent_cfg.get("fs", []), field_name="fs", sb_name=current),
            ),
            "net": _merge_unique(
                _norm_rule_list(
                    defaults.get("net", defaults.get("tcp", [])),
                    field_name="net",
                    sb_name=current,
                ),
                _norm_rule_list(
                    parent_cfg.get("net", parent_cfg.get("tcp", [])),
                    field_name="net",
                    sb_name=current,
                ),
            ),
            "imports": _merge_unique(
                _norm_rule_list(
                    defaults.get("imports", []), field_name="imports", sb_name=current
                ),
                _norm_rule_list(
                    parent_cfg.get("imports", []), field_name="imports", sb_name=current
                ),
            ),
        }
        child_fs = _norm_rule_list(cfg.get("fs", []), field_name="fs", sb_name=current)
        child_net = _norm_rule_list(
            cfg.get("net", cfg.get("tcp", [])), field_name="net", sb_name=current
        )
        child_imports = _norm_rule_list(
            cfg.get("imports", []), field_name="imports", sb_name=current
        )
        out = {
            "fs": _merge_unique(base["fs"], child_fs),
            "net": _merge_unique(base["net"], child_net),
            "imports": _merge_unique(base["imports"], child_imports),
        }
        resolving.remove(current)
        resolved[current] = out
        return out

    return _resolve(name)


def compile_policy(path: str | Path) -> CompiledPolicy:
    """Parse and validate a policy YAML file."""

    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if hasattr(yaml, "__file__"):
        data = yaml.safe_load(text) or {}
    else:
        if "sandboxes:" in text:
            data = _simple_parse(text)
        else:
            data = yaml.safe_load(text)

    if not isinstance(data, dict):
        raise PolicyCompilerError("policy document must be a mapping")

    schema_version = str(data.get("version", "0.1"))
    if schema_version not in {"0.1", "1", "1.0"}:
        raise PolicyCompilerError(f"unsupported policy version: {schema_version}")

    defaults = data.get("defaults", {})
    if defaults is None:
        defaults = {}
    if not isinstance(defaults, dict):
        raise PolicyCompilerError("'defaults' must be a mapping")

    sandboxes = data.get("sandboxes")
    if sandboxes is None:
        sb_cfg = {k: v for k, v in data.items() if k != "version"}
        sandboxes = {"default": sb_cfg}
    if not isinstance(sandboxes, dict):
        raise PolicyCompilerError("missing or invalid 'sandboxes' section")

    compiled_boxes: Dict[str, SandboxPolicy] = {}
    deny_log: list[str] = []
    for name, cfg in sandboxes.items():
        if not isinstance(cfg, dict):
            raise PolicyCompilerError(f"sandbox '{name}' must be a mapping")
        resolved_cfg = _resolve_sandbox(name, sandboxes, defaults)
        fs_raw = resolved_cfg.get("fs", [])
        fs_compiled = _compile_fs(fs_raw, name)
        tcp_raw = resolved_cfg.get("net", [])
        tcp_compiled = _compile_tcp(tcp_raw, name)

        imports_raw = resolved_cfg.get("imports", [])
        imports: list[str] = []
        for module in imports_raw:
            if not isinstance(module, str):
                raise PolicyCompilerError(
                    f"import rules in '{name}' must be strings: {module!r}"
                )
            imports.append(module)

        compiled_boxes[name] = SandboxPolicy(
            fs=fs_compiled, tcp=tcp_compiled, imports=imports
        )
        deny_log.extend(
            [f"sandbox={name} fs={r.path}" for r in fs_compiled if r.action == "deny"]
        )
        deny_log.extend(
            [f"sandbox={name} net={r.addr}" for r in tcp_compiled if r.action == "deny"]
        )

    return CompiledPolicy(
        schema_version="1.0" if schema_version == "1" else schema_version,
        semantics_version=1,
        sandboxes=compiled_boxes,
        deny_log=sorted(set(deny_log)),
    )


__all__ = ["CompiledPolicy", "compile_policy", "PolicyCompilerError"]
