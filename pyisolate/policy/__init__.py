"""Policy helpers stub."""

import os
import socket
import tempfile
import urllib.request
from dataclasses import asdict, dataclass, field
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
                if ":" not in item:
                    raise ValueError("invalid YAML line")
                k, v = item.split(":", 1)
                from typing import cast

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


from .compiler import PolicyCompilerError, compile_policy


@dataclass
class Policy:
    mem: str | None = None
    fs: list[str] = field(default_factory=list)
    tcp: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)

    def allow_fs(self, path: str) -> "Policy":
        self.fs.append(path)
        return self

    def allow_tcp(self, addr: str) -> "Policy":
        self.tcp.append(addr)
        return self

    def allow_import(self, module: str) -> "Policy":
        self.imports.append(module)
        return self


def _validate(data: object) -> None:
    """Validate parsed YAML schema."""
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping")

    if "version" not in data:
        raise ValueError('policy missing "version" key')

    version = data.get("version")
    if str(version) != "0.1":
        raise ValueError(f"unsupported policy version: {version}")

    for section in ("defaults", "sandboxes"):
        if section in data and not isinstance(data[section], dict):
            raise ValueError(f'"{section}" must be a mapping')


def refresh(path: str, token: str) -> None:
    """Parse *path* and atomically update eBPF policy maps."""

    # Compile and validate the YAML policy first
    compiled = compile_policy(path)

    import json

    # Write the compiled representation for the BPF manager
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tmp:
        json.dump(asdict(compiled), tmp)
        json_path = Path(tmp.name)

    # Fail fast if the YAML is malformed before touching BPF maps
    with open(path, "r", encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh)
        except Exception as exc:  # broad due to optional parser
            raise ValueError(f"invalid YAML: {exc}") from None

    _validate(data)

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


def refresh_remote(url: str, token: str, timeout: float | None = None, max_retries: int = 0) -> None:
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
        refresh(tmp_path, token)
    finally:
        os.unlink(tmp_path)


__all__ = [
    "Policy",
    "refresh",
    "compile_policy",
    "PolicyCompilerError",
    "refresh_remote",
]
