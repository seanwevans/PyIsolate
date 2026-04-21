"""Concrete capability objects used to grant sandbox access.

The default sandbox environment is deny-by-default for side effects. Access to
filesystem, network, secrets, subprocesses, IPC, and entropy/clock primitives
is granted only by explicitly providing capability instances.
"""

from __future__ import annotations

import os
import queue
import secrets as _secrets
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, Literal, TypeVar

T = TypeVar("T")


class Capability(Generic[T]):
    """Marker protocol for typed capability tokens."""


@dataclass(frozen=True)
class Token(Capability[T]):
    """Immutable token carrying a phantom type."""

    name: str


class RootCapability(Token[Literal["root"]]):
    """Capability granting privileged supervisor operations."""


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
            command_name = args.split(maxsplit=1)[0]
            if command_name not in self.allowed_commands:
                raise PermissionError(f"subprocess blocked: {command_name}")
        else:
            seq = list(args)
            if not seq:
                raise ValueError("empty command")
            command_name = seq[0]
            if command_name not in self.allowed_commands:
                raise PermissionError(f"subprocess blocked: {command_name}")

        return subprocess.run(
            args,
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            shell=isinstance(args, str),
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
    "FilesystemCapability",
    "NetworkCapability",
    "SecretCapability",
    "SubprocessCapability",
    "IPCChannelCapability",
    "ClockCapability",
    "RandomCapability",
]
