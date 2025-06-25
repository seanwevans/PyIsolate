"""Policy helpers stub."""

from dataclasses import dataclass
from pathlib import Path

try:
    import yaml  # type: ignore
except ModuleNotFoundError:  # minimal fallback when PyYAML is unavailable

    def _mini_load(text: str) -> dict:
        result = {}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ":" not in line:
                raise ValueError("invalid YAML line")
            k, v = line.split(":", 1)
            result[k.strip()] = v.strip()
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

    def allow_fs(self, path: str) -> "Policy":
        return self

    def allow_tcp(self, addr: str) -> "Policy":
        return self


def refresh(path: str) -> None:
    """Parse *path* and atomically update eBPF policy maps."""

    # Fail fast if the YAML is malformed before touching BPF maps
    with open(path, "r", encoding="utf-8") as fh:
        yaml.safe_load(fh)

    # Upon successful parse, swap the live maps via the supervisor
    reload_policy(str(Path(path).resolve()))


__all__ = ["Policy", "refresh"]
