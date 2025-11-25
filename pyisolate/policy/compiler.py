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
    sandboxes: Dict[str, SandboxPolicy]


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
        if addr in seen and seen[addr] != action:
            raise PolicyCompilerError(
                f"conflicting net rules for '{addr}' in '{sb_name}'"
            )
        seen[addr] = action
        compiled.append(TCPRule(action=action, addr=addr))
    return compiled


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

    sandboxes = data.get("sandboxes")
    if sandboxes is None:
        sb_cfg = {k: v for k, v in data.items() if k != "version"}
        sandboxes = {"default": sb_cfg}
    if not isinstance(sandboxes, dict):
        raise PolicyCompilerError("missing or invalid 'sandboxes' section")

    compiled_boxes: Dict[str, SandboxPolicy] = {}
    for name, cfg in sandboxes.items():
        if not isinstance(cfg, dict):
            raise PolicyCompilerError(f"sandbox '{name}' must be a mapping")
        fs_raw = cfg.get("fs", [])
        if not isinstance(fs_raw, list):
            raise PolicyCompilerError(f"'fs' in '{name}' must be a list")
        fs_compiled = _compile_fs(fs_raw, name)
        tcp_raw = cfg.get("net", cfg.get("tcp", []))
        if not isinstance(tcp_raw, list):
            raise PolicyCompilerError(f"'net' in '{name}' must be a list")
        tcp_compiled = _compile_tcp(tcp_raw, name)

        imports_raw = cfg.get("imports", [])
        if not isinstance(imports_raw, list):
            raise PolicyCompilerError(f"'imports' in '{name}' must be a list")
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

    return CompiledPolicy(sandboxes=compiled_boxes)


__all__ = ["CompiledPolicy", "compile_policy", "PolicyCompilerError"]
