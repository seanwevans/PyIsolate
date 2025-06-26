"""Policy helpers stub."""

from dataclasses import dataclass, field
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
                from typing import cast, List, Dict
                assert isinstance(result[current], list)
                lst = cast(list[dict[str, str]], result[current])
                lst.append({k.strip(): _unquote(v.strip())})
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

    # Fail fast if the YAML is malformed before touching BPF maps
    with open(path, "r", encoding="utf-8") as fh:
        yaml.safe_load(fh)

    # Upon successful parse, swap the live maps via the supervisor
    reload_policy(str(Path(path).resolve()))


__all__ = ["Policy", "refresh"]
