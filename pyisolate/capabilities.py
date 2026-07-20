"""Concrete capability objects used to grant sandbox access.

The default sandbox environment is deny-by-default for side effects. Access to
filesystem, network, secrets, subprocesses, IPC, and entropy/clock primitives
is granted only by explicitly providing capability instances.
"""

from __future__ import annotations

import os
import queue
import secrets as _secrets
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generic, Iterable, Literal, TypeVar

T = TypeVar("T")


class Capability(Generic[T]):
    """Marker protocol for typed capability tokens."""


@dataclass(frozen=True)
class Token(Capability[T]):
    """Immutable token carrying a phantom type."""

    name: str


class RootCapability(Token[Literal["root"]]):
    """Capability granting privileged supervisor operations."""


class Authority(Capability[str]):
    """Base class for first-class sandbox authority grants."""

    kind: str

    def to_policy_rule(self) -> dict[str, Any] | str:
        """Return a YAML-serializable representation of this authority."""
        raise NotImplementedError


@dataclass(frozen=True)
class ReadPath(Authority):
    """Grant read access below a filesystem path."""

    path: Path | str
    kind: str = "read_path"

    @property
    def root(self) -> Path:
        return Path(self.path).resolve(strict=False)

    def allows(self, path: str | os.PathLike[str]) -> bool:
        return Path(path).resolve(strict=False).is_relative_to(self.root)

    def to_policy_rule(self) -> dict[str, str]:
        return {"read": str(self.path)}


@dataclass(frozen=True)
class WritePath(Authority):
    """Grant write access below a filesystem path."""

    path: Path | str
    kind: str = "write_path"

    @property
    def root(self) -> Path:
        return Path(self.path).resolve(strict=False)

    def allows(self, path: str | os.PathLike[str]) -> bool:
        return Path(path).resolve(strict=False).is_relative_to(self.root)

    def to_policy_rule(self) -> dict[str, str]:
        return {"write": str(self.path)}


@dataclass(frozen=True)
class ConnectTCP(Authority):
    """Grant outgoing TCP connect authority to a host and port."""

    host: str
    port: int
    kind: str = "connect_tcp"

    @classmethod
    def from_address(cls, address: str) -> "ConnectTCP":
        host, sep, port_text = address.rpartition(":")
        if not sep or not host or not port_text.isdigit():
            raise ValueError(f"TCP address must be 'host:port': {address!r}")
        return cls(host=host, port=int(port_text))

    @property
    def address(self) -> str:
        return f"{self.host}:{self.port}"

    def allows(self, host: str, port: int) -> bool:
        return self.host == host and self.port == port

    def to_policy_rule(self) -> dict[str, str]:
        return {"connect": self.address}


@dataclass(frozen=True)
class Import(Authority):
    """Grant authority to import a module root."""

    module: str
    kind: str = "import"

    def __post_init__(self) -> None:
        if not self.module or not isinstance(self.module, str):
            raise ValueError("module must be a non-empty string")

    @property
    def root_module(self) -> str:
        return self.module.split(".", 1)[0]

    def to_policy_rule(self) -> str:
        return self.module


@dataclass(frozen=True)
class CpuBudget(Authority):
    """Grant a bounded CPU budget in milliseconds."""

    ms: int
    kind: str = "cpu_budget"

    def __post_init__(self) -> None:
        if self.ms <= 0:
            raise ValueError("CPU budget must be positive")

    def to_policy_rule(self) -> dict[str, int]:
        return {"cpu_ms": self.ms}


@dataclass(frozen=True)
class AuthoritySet:
    """Normalized authority model shared by Python objects and YAML policy."""

    read_paths: tuple[Path, ...] = ()
    write_paths: tuple[Path, ...] = ()
    tcp: frozenset[str] = frozenset()
    imports: frozenset[str] = frozenset()
    cpu_ms: int | None = None

    @classmethod
    def from_authorities(cls, authorities: Iterable[object]) -> "AuthoritySet":
        read_paths: list[Path] = []
        write_paths: list[Path] = []
        tcp: set[str] = set()
        imports: set[str] = set()
        cpu_ms: int | None = None
        for authority in authorities:
            if isinstance(authority, ReadPath):
                read_paths.append(authority.root)
            elif isinstance(authority, WritePath):
                write_paths.append(authority.root)
            elif isinstance(authority, ConnectTCP):
                tcp.add(authority.address)
            elif isinstance(authority, Import):
                imports.add(authority.root_module)
            elif isinstance(authority, CpuBudget):
                cpu_ms = authority.ms if cpu_ms is None else min(cpu_ms, authority.ms)
            elif isinstance(authority, FilesystemCapability):
                read_paths.extend(authority.roots)
                write_paths.extend(authority.roots)
            elif isinstance(authority, NetworkCapability):
                tcp.update(authority.destinations)
        return cls(
            read_paths=tuple(read_paths),
            write_paths=tuple(write_paths),
            tcp=frozenset(tcp),
            imports=frozenset(imports),
            cpu_ms=cpu_ms,
        )

    def allows_read(self, path: str | os.PathLike[str]) -> bool:
        resolved = Path(path).resolve(strict=False)
        return any(resolved.is_relative_to(root) for root in self.read_paths)

    def allows_write(self, path: str | os.PathLike[str]) -> bool:
        resolved = Path(path).resolve(strict=False)
        return any(resolved.is_relative_to(root) for root in self.write_paths)

    def allows_tcp(self, host: str, port: int) -> bool:
        return f"{host}:{port}" in self.tcp

    def merge(self, other: "AuthoritySet") -> "AuthoritySet":
        cpu_ms = self.cpu_ms
        if other.cpu_ms is not None:
            cpu_ms = other.cpu_ms if cpu_ms is None else min(cpu_ms, other.cpu_ms)
        return AuthoritySet(
            read_paths=self.read_paths + other.read_paths,
            write_paths=self.write_paths + other.write_paths,
            tcp=frozenset(set(self.tcp) | set(other.tcp)),
            imports=frozenset(set(self.imports) | set(other.imports)),
            cpu_ms=cpu_ms,
        )


@dataclass(frozen=True)
class FilesystemCapability(Capability[Literal["filesystem"]]):
    """Capability that permits file access only within *roots*."""

    roots: tuple[Path, ...]

    @classmethod
    def from_paths(cls, *paths: str | os.PathLike[str]) -> "FilesystemCapability":
        roots = tuple(Path(path).resolve(strict=False) for path in paths)
        return cls(roots=roots)

    def allows(self, path: str | os.PathLike[str]) -> bool:
        resolved = Path(path).resolve(strict=False)
        return any(resolved.is_relative_to(root) for root in self.roots)


@dataclass(frozen=True)
class NetworkCapability(Capability[Literal["network"]]):
    """Capability that permits outgoing TCP connections to explicit targets."""

    destinations: frozenset[str]

    @classmethod
    def from_destinations(cls, *destinations: str) -> "NetworkCapability":
        return cls(destinations=frozenset(destinations))

    def allows(self, host: str, port: int) -> bool:
        return f"{host}:{port}" in self.destinations


@dataclass(frozen=True)
class SecretCapability(Capability[Literal["secrets"]]):
    """Capability wrapper for named secret values."""

    values: dict[str, bytes]

    @classmethod
    def from_mapping(
        cls, mapping: dict[str, str | bytes | bytearray | memoryview]
    ) -> "SecretCapability":
        normalized: dict[str, bytes] = {}
        for key, value in mapping.items():
            if isinstance(value, str):
                normalized[key] = value.encode("utf-8")
            else:
                normalized[key] = bytes(value)
        return cls(values=normalized)

    def get(self, name: str) -> bytes:
        if name not in self.values:
            raise KeyError(name)
        return self.values[name]


@dataclass(frozen=True)
class SubprocessCapability(Capability[Literal["subprocess"]]):
    """Capability that brokers subprocess execution via an allowlist."""

    allowed_commands: frozenset[str]
    allow_shell: bool = False

    @classmethod
    def from_commands(
        cls, *commands: str, allow_shell: bool = False
    ) -> "SubprocessCapability":
        return cls(allowed_commands=frozenset(commands), allow_shell=allow_shell)

    def run(
        self,
        args: str | list[str] | tuple[str, ...],
        *,
        check: bool = False,
        capture_output: bool = True,
        text: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess:
        if isinstance(args, str):
            if not self.allow_shell:
                raise PermissionError("shell string commands are not permitted")
            # Tokenize the string ourselves instead of handing it to a shell.
            # Validating only the first whitespace token and then running with
            # ``shell=True`` let metacharacters bypass the allowlist entirely
            # (e.g. ``"echo hi; rm -rf ~"`` passed the ``echo`` check but the
            # shell still executed ``rm``).
            try:
                argv = shlex.split(args)
            except ValueError as exc:
                raise PermissionError(f"subprocess blocked: unparseable command: {exc}")
        else:
            argv = list(args)
        if not argv:
            raise ValueError("empty command")
        command_name = argv[0]
        if command_name not in self.allowed_commands:
            raise PermissionError(f"subprocess blocked: {command_name}")

        return subprocess.run(
            argv,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            shell=False,
        )


@dataclass
class IPCChannelCapability(Capability[Literal["ipc"]]):
    """In-memory brokered message channel capability."""

    _queue: "queue.Queue[object]" = field(default_factory=queue.Queue)

    def send(self, message: object) -> None:
        self._queue.put(message)

    def recv(self, timeout: float | None = None) -> object:
        return self._queue.get(timeout=timeout)


@dataclass(frozen=True)
class ClockCapability(Capability[Literal["clock"]]):
    """Capability that exposes clock primitives."""

    def time(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True)
class RandomCapability(Capability[Literal["random"]]):
    """Capability that exposes secure entropy primitives."""

    def bytes(self, length: int) -> bytes:
        return _secrets.token_bytes(length)


ROOT = RootCapability(name="root")

__all__ = [
    "Capability",
    "Token",
    "RootCapability",
    "ROOT",
    "Authority",
    "AuthoritySet",
    "ReadPath",
    "WritePath",
    "ConnectTCP",
    "Import",
    "CpuBudget",
    "FilesystemCapability",
    "NetworkCapability",
    "SecretCapability",
    "SubprocessCapability",
    "IPCChannelCapability",
    "ClockCapability",
    "RandomCapability",
]
