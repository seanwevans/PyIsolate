"""Policy helpers stub."""

import os
import socket
import tempfile
import urllib.request
import logging
from importlib import resources
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import URLError

try:
    import yaml  # type: ignore
except ModuleNotFoundError:  # minimal fallback when PyYAML is unavailable

    def _unquote(value: str) -> str:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            return value[1:-1]
        return value

    def _mini_load(text: str) -> dict:
        result: dict[str, object] = {}
        current: str | None = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("-"):
                if current is None or not isinstance(result.get(current), list):
                    raise ValueError("invalid YAML line")
                item = line[1:].strip()
                if ":" in item:
                    k, v = item.split(":", 1)
                    from typing import cast

                    assert isinstance(result[current], list)
                    lst = cast(list[dict[str, str]], result[current])
                    lst.append({k.strip(): _unquote(v.strip())})
                else:
                    from typing import cast

                    assert isinstance(result[current], list)
                    lst = cast(list[str], result[current])
                    lst.append(_unquote(item))
                continue

            if ":" not in line:
                raise ValueError("invalid YAML line")
            k, v = line.split(":", 1)
            key = k.strip()
            val = v.strip()
            if val == "":
                result[key] = []
                current = key
            else:
                result[key] = _unquote(val)
                current = key
        return result

    class _MiniYaml:
        @staticmethod
        def safe_load(stream):
            if hasattr(stream, "read"):
                return _mini_load(stream.read())
            return _mini_load(stream)

    yaml = _MiniYaml()


from .compiler import (
    CompiledPolicy,
    PolicyCompilerError,
    SandboxPolicy,
    compile_policy,
)  # noqa: F401

from ..capabilities import ConnectTCP, CpuBudget, Import, ReadPath, WritePath
from .model import (  # noqa: F401
    FilesystemRule,
    NetworkRule,
    RuntimePolicy,
    RuntimePolicySet,
    from_compiled_policy,
    from_sandbox_policy,
    from_yaml_dict,
    to_bpf_map_entries,
)
logger = logging.getLogger(__name__)


@dataclass
class Policy:
    mem: str | None = None
    fs: list[str] = field(default_factory=list)
    tcp: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    capabilities: list[object] = field(default_factory=list)

    def grant(self, *capabilities: object) -> "Policy":
        """Add first-class authority objects to this policy."""
        self.capabilities.extend(capabilities)
        for capability in capabilities:
            if isinstance(capability, (ReadPath, WritePath)):
                continue
            if isinstance(capability, ConnectTCP):
                if capability.address not in self.tcp:
                    self.tcp.append(capability.address)
            elif isinstance(capability, Import):
                if capability.module not in self.imports:
                    self.imports.append(capability.module)
        return self

    def allow_fs(self, path: str) -> "Policy":
        self.fs.append(path)
        self.capabilities.extend([ReadPath(path), WritePath(path)])
        return self

    def allow_read(self, path: str) -> "Policy":
        self.capabilities.append(ReadPath(path))
        return self

    def allow_write(self, path: str) -> "Policy":
        self.capabilities.append(WritePath(path))
        return self

    def allow_tcp(self, addr: str) -> "Policy":
        self.tcp.append(addr)
        try:
            self.capabilities.append(ConnectTCP.from_address(addr))
        except ValueError:
            pass
        return self

    def allow_import(self, module: str) -> "Policy":
        self.imports.append(module)
        self.capabilities.append(Import(module))
        return self

    def cpu_budget(self, ms: int) -> "Policy":
        self.capabilities.append(CpuBudget(ms))
        return self

    def to_dict(self, name: str = "default") -> dict[str, object]:
        """Serialize this authority model to the YAML policy schema."""
        fs_rules: list[object] = []
        net_rules: list[object] = []
        imports: list[str] = []
        cpu_ms: int | None = None
        for path in self.fs:
            fs_rules.append({"allow": path})
        for addr in self.tcp:
            net_rules.append({"connect": addr})
        imports.extend(self.imports)
        for capability in self.capabilities:
            if isinstance(capability, ReadPath):
                fs_rules.append(capability.to_policy_rule())
            elif isinstance(capability, WritePath):
                fs_rules.append(capability.to_policy_rule())
            elif isinstance(capability, ConnectTCP):
                rule = capability.to_policy_rule()
                if rule not in net_rules:
                    net_rules.append(rule)
            elif isinstance(capability, Import):
                if capability.module not in imports:
                    imports.append(capability.module)
            elif isinstance(capability, CpuBudget):
                cpu_ms = capability.ms if cpu_ms is None else min(cpu_ms, capability.ms)

        sandbox: dict[str, object] = {}
        if fs_rules:
            sandbox["fs"] = fs_rules
        if net_rules:
            sandbox["net"] = net_rules
        if imports:
            sandbox["imports"] = imports
        if cpu_ms is not None:
            sandbox["cpu_ms"] = cpu_ms
        return {"version": "1.0", "sandboxes": {name: sandbox}}

    def to_yaml(self, name: str = "default") -> str:
        """Serialize this policy to YAML using the configured YAML backend."""
        data = self.to_dict(name)
        if hasattr(yaml, "safe_dump"):
            return yaml.safe_dump(data, sort_keys=False)

        lines = ["version: 1.0", "sandboxes:", f"  {name}:"]
        sandbox = data["sandboxes"][name]  # type: ignore[index]
        for rule in sandbox.get("fs", []):
            key, value = next(iter(rule.items()))
            lines.append("    fs:" if "    fs:" not in lines else "")
            lines.append(f"      - {key}: {value!r}")
        if sandbox.get("net"):
            lines.append("    net:")
            for rule in sandbox["net"]:
                key, value = next(iter(rule.items()))
                lines.append(f"      - {key}: {value!r}")
        if sandbox.get("imports"):
            lines.append("    imports:")
            for module in sandbox["imports"]:
                lines.append(f"      - {module}")
        if sandbox.get("cpu_ms") is not None:
            lines.append(f"    cpu_ms: {sandbox['cpu_ms']}")
        return "\n".join(line for line in lines if line) + "\n"


def _validate(data: object) -> None:
    """Validate parsed YAML schema."""
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping")

    if "version" not in data:
        raise ValueError('policy missing "version" key')

    version = str(data.get("version"))
    if version not in {"0.1", "1", "1.0"}:
        raise ValueError(f"unsupported policy version: {version}")

    for section in ("defaults", "sandboxes"):
        if section in data and not isinstance(data[section], dict):
            raise ValueError(f'"{section}" must be a mapping')


def refresh(path: str, token: str, *, dry_run: bool = False):
    """Parse *path* and atomically update eBPF policy maps."""

    # Fail fast if the YAML is malformed/schema-invalid before compiling/reloading.
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except Exception as exc:  # broad due to optional parser
            raise ValueError(f"invalid YAML: {exc}") from None

    _validate(data)

    # Compile only after schema/version validation passes.
    compiled = compile_policy(path)

    import json

    if compiled.deny_log:
        for line in compiled.deny_log:
            logger.warning("policy deny rule active: %s", line)

    if dry_run:
        return compiled

    # Write the compiled representation for the BPF manager
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
        json.dump(from_compiled_policy(compiled).to_dict(), tmp)
        json_path = Path(tmp.name)

    # Upon successful parse, swap the live maps via the supervisor
    try:
        from ..supervisor import reload_policy

        reload_policy(str(json_path.resolve()), token)
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass


def _is_timeout_error(exc: Exception) -> bool:
    if isinstance(exc, socket.timeout):
        return True
    if isinstance(exc, URLError) and isinstance(exc.reason, socket.timeout):
        return True
    return False


def refresh_remote(
    url: str,
    token: str,
    timeout: float | None = None,
    max_retries: int = 0,
    *,
    dry_run: bool = False,
):
    """Fetch policy YAML from *url* and apply it."""
    attempts = max(1, max_retries + 1)

    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as fh:
                text = fh.read().decode("utf-8")
            break
        except Exception as exc:  # narrow to timeout conditions only
            if _is_timeout_error(exc):
                if attempt < attempts - 1:
                    continue
                raise TimeoutError(
                    f"policy download from {url} timed out after {attempts} "
                    f"attempt(s); timeout={timeout}s"
                ) from exc
            raise

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml") as tmp:
        tmp.write(text)
        tmp_path = tmp.name

    try:
        return refresh(tmp_path, token, dry_run=dry_run)
    finally:
        os.unlink(tmp_path)


def _policy_root():
    """Return the package-managed directory that stores named policy templates."""

    return resources.files(__package__) / "templates"


NAMED_POLICIES: dict[str, str] = {
    "stdlib.readonly": "stdlib.readonly.yml",
    "ml-inference": "ml-inference.yml",
    "readonly-fs": "readonly-fs.yml",
}


def _select_sandbox_policy(compiled, selector: str | None = None):
    sandboxes = compiled.sandboxes
    if selector and selector in sandboxes:
        return sandboxes[selector]
    if "default" in sandboxes:
        return sandboxes["default"]
    if len(sandboxes) == 1:
        return next(iter(sandboxes.values()))
    available = ", ".join(sorted(sandboxes))
    raise PolicyCompilerError(
        "policy document contains multiple sandboxes; " f"select one of: {available}"
    )


def _runtime_policy_from_sandbox(sandbox_policy: SandboxPolicy) -> Policy:
    runtime = Policy()
    for rule in sandbox_policy.fs:
        if rule.action == "allow":
            runtime.allow_fs(rule.path)
    for rule in sandbox_policy.tcp:
        if rule.action == "connect":
            runtime.allow_tcp(rule.addr)
    for module in sandbox_policy.imports:
        runtime.allow_import(module)
    return runtime


def _runtime_policy_from_dict(data: dict) -> Policy:
    if "sandboxes" in data:
        sandboxes = data.get("sandboxes")
        if not isinstance(sandboxes, dict):
            raise PolicyCompilerError("missing or invalid 'sandboxes' section")
        selector = "default" if "default" in sandboxes else None
        if selector is None and len(sandboxes) == 1:
            selector = next(iter(sandboxes))
        if selector is None:
            available = ", ".join(sorted(str(k) for k in sandboxes))
            raise PolicyCompilerError(
                "policy mapping contains multiple sandboxes; "
                f"select one of: {available}"
            )
        selected = sandboxes[selector]
        if not isinstance(selected, dict):
            raise PolicyCompilerError(f"sandbox '{selector}' must be a mapping")
        merged = dict(data.get("defaults") or {})
        merged.update(selected)
        data = merged

    runtime = Policy()
    fs_rules = data.get("fs", []) or []
    if not isinstance(fs_rules, list):
        raise PolicyCompilerError("'fs' must be a list")
    for rule in fs_rules:
        if isinstance(rule, str):
            runtime.allow_fs(rule)
        elif isinstance(rule, dict) and len(rule) == 1:
            action, path = next(iter(rule.items()))
            if action == "allow" and isinstance(path, str):
                runtime.allow_fs(path)
            elif action not in {"allow", "deny"}:
                raise PolicyCompilerError(f"invalid fs action '{action}'")
        else:
            raise PolicyCompilerError(f"invalid fs rule: {rule!r}")

    net_rules = data.get("net", data.get("tcp", [])) or []
    if not isinstance(net_rules, list):
        raise PolicyCompilerError("'net' must be a list")
    for rule in net_rules:
        if isinstance(rule, str):
            runtime.allow_tcp(rule)
        elif isinstance(rule, dict) and len(rule) == 1:
            action, addr = next(iter(rule.items()))
            if action == "connect":
                addresses = addr if isinstance(addr, list) else [addr]
                for address in addresses:
                    if not isinstance(address, str):
                        raise PolicyCompilerError(
                            f"net addresses must be strings: {address!r}"
                        )
                    runtime.allow_tcp(address)
            elif action != "deny":
                raise PolicyCompilerError(f"invalid net action '{action}'")
        else:
            raise PolicyCompilerError(f"invalid net rule: {rule!r}")

    imports = data.get("imports", []) or []
    if not isinstance(imports, list):
        raise PolicyCompilerError("'imports' must be a list")
    for module in imports:
        if not isinstance(module, str):
            raise PolicyCompilerError(f"import rules must be strings: {module!r}")
        runtime.allow_import(module)
    return runtime


def _resolve_policy_path(name: str) -> Path:
    candidate = Path(name)
    if candidate.exists():
        return candidate

    policy_root = _policy_root()
    mapped = NAMED_POLICIES.get(name)
    if mapped is not None:
        path = policy_root / mapped
        if path.exists():
            return path
        raise PolicyCompilerError(
            f"named policy '{name}' is registered but {path} does not exist"
        )

    for suffix in (".yml", ".yaml"):
        path = policy_root / f"{name}{suffix}"
        if path.exists():
            return path

    supported = ", ".join(sorted(NAMED_POLICIES))
    raise PolicyCompilerError(
        f"unknown policy '{name}'. Supported named policies: {supported}"
    )


def resolve_policy(policy: str | Policy | SandboxPolicy | CompiledPolicy | dict | None):
    """Resolve public policy inputs to the runtime policy applied by a sandbox.

    String inputs are fail-closed: they must name an existing file in ``policy/``
    or a supported named policy, otherwise :class:`PolicyCompilerError` is raised.
    """

    if policy is None or isinstance(policy, Policy):
        return policy
    if isinstance(policy, SandboxPolicy):
        return _runtime_policy_from_sandbox(policy)
    if isinstance(policy, CompiledPolicy):
        return _runtime_policy_from_sandbox(_select_sandbox_policy(policy))
    if isinstance(policy, dict):
        return _runtime_policy_from_dict(policy)
    if isinstance(policy, str):
        path = _resolve_policy_path(policy)
        compiled = compile_policy(path)
        selector = path.stem if path.stem in compiled.sandboxes else policy
        return _runtime_policy_from_sandbox(_select_sandbox_policy(compiled, selector))
    raise ValueError(f"unsupported policy type: {type(policy).__name__}")


__all__ = [
    "Policy",
    "ReadPath",
    "WritePath",
    "ConnectTCP",
    "Import",
    "CpuBudget",
    "refresh",
    "compile_policy",
    "PolicyCompilerError",
    "refresh_remote",
    "resolve_policy",
    "NAMED_POLICIES",
    "SandboxPolicy",
    "CompiledPolicy",
]
