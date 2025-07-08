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
class SandboxPolicy:
    fs: List[FSRule]


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
            if ":" not in token[2:]:
                raise PolicyCompilerError("invalid rule line")
            k, v = token[2:].split(":", 1)
            v = v.strip().strip('"').strip("'")
            data["sandboxes"][current_sb][current_section].append({k.strip(): v})
        else:
            raise PolicyCompilerError("invalid indentation or syntax")
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


def compile_policy(path: str | Path) -> CompiledPolicy:
    """Parse and validate a policy YAML file."""

    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
        if "sandboxes:" in text and not hasattr(yaml, "__file__"):
            data = _simple_parse(text)
        else:
            data = yaml.safe_load(text) or {}

    if not isinstance(data, dict):
        raise PolicyCompilerError("policy document must be a mapping")

    sandboxes = data.get("sandboxes")
    if sandboxes is None:
        sandboxes = {"default": {k: v for k, v in data.items() if k != "version"}}
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
        compiled_boxes[name] = SandboxPolicy(fs=fs_compiled)

    return CompiledPolicy(sandboxes=compiled_boxes)


__all__ = ["CompiledPolicy", "compile_policy", "PolicyCompilerError"]
