"""Policy helpers stub."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from ..supervisor import reload_policy
from .compiler import PolicyCompilerError, compile_policy

import urllib.request
import tempfile
import os

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
                if ":" not in item:
                    raise ValueError("invalid YAML line")
                k, v = item.split(":", 1)
                result[current].append({k.strip(): _unquote(v.strip())})
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



@dataclass
class Policy:
    mem: str | None = None
    fs: list[str] = field(default_factory=list)
    tcp: list[str] = field(default_factory=list)

    def allow_fs(self, path: str) -> "Policy":
        self.fs.append(path)
        return self

    def allow_tcp(self, addr: str) -> "Policy":
        self.tcp.append(addr)
        return self


def _validate(data: object) -> None:
    """Validate parsed YAML schema."""
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping")

    if "version" not in data:
        raise ValueError('policy missing "version" key')

    if data.get("version") != "0.1":
        raise ValueError(f"unsupported policy version: {data.get('version')}")

    for section in ("defaults", "sandboxes"):
        if section in data and not isinstance(data[section], dict):
            raise ValueError(f'"{section}" must be a mapping')


def refresh(path: str) -> None:
    """Parse *path* and atomically update eBPF policy maps."""

    # Compile and validate the YAML policy first
    compiled = compile_policy(path)

    # Write the compiled representation to a JSON file for the BPF manager
    json_path = Path(path).with_suffix(".json")
    with open(json_path, "w", encoding="utf-8") as fh:
        import json

        json.dump(asdict(compiled), fh)

    # Upon successful parse, swap the live maps via the supervisor
    reload_policy(str(json_path.resolve()))


    # Fail fast if the YAML is malformed before touching BPF maps
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except Exception as exc:  # broad due to optional parser
            raise ValueError(f"invalid YAML: {exc}") from None

    _validate(data)

    # Upon successful parse, swap the live maps via the supervisor
    reload_policy(str(Path(path).resolve()), token)


def refresh_remote(url: str) -> None:
    """Fetch policy YAML from *url* and apply it."""
    with urllib.request.urlopen(url) as fh:
        text = fh.read().decode("utf-8")

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yml") as tmp:
        tmp.write(text)
        tmp_path = tmp.name

    try:
        refresh(tmp_path)
    finally:
        os.unlink(tmp_path)

__all__ = [
    "Policy",
    "refresh",
    "compile_policy",
    "PolicyCompilerError",
    "refresh_remote"
]
