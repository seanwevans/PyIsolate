"""Policy helpers stub."""

from dataclasses import dataclass


@dataclass
class Policy:
    mem: str | None = None

    def allow_fs(self, path: str) -> "Policy":
        return self

    def allow_tcp(self, addr: str) -> "Policy":
        return self
