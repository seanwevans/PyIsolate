"""Policy helpers stub."""

from dataclasses import asdict, dataclass, field
from pathlib import Path

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

from ..supervisor import reload_policy
from .compiler import PolicyCompilerError, compile_policy


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


__all__ = [
    "Policy",
    "refresh",
    "compile_policy",
    "PolicyCompilerError",
]
