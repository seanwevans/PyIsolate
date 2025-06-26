"""Typed capability tokens for mypy-based checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar, Literal


T = TypeVar("T")


class Capability(Generic[T]):
    """Protocol for capability tokens."""


@dataclass(frozen=True)
class Token(Capability[T]):
    """Immutable token carrying a phantom type."""

    name: str


class RootCapability(Token[Literal["root"]]):
    """Capability granting privileged supervisor operations."""


ROOT = RootCapability(name="root")

__all__ = ["Capability", "Token", "RootCapability", "ROOT"]
