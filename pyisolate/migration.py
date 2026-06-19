"""Sandbox migration utilities."""

from __future__ import annotations

from .checkpoint import checkpoint, restore
from .supervisor import Sandbox

_LOCAL_HOSTS = {"", "localhost", "127.0.0.1", "::1"}


def migrate(sandbox: Sandbox, host: str, key: bytes) -> Sandbox:
    """Migrate *sandbox* to *host* using an encrypted checkpoint.

    Only local checkpoint/restore migration is currently supported. Passing a
    non-local *host* raises :class:`NotImplementedError` instead of silently
    restoring the sandbox on the local machine.
    """
    if host not in _LOCAL_HOSTS:
        raise NotImplementedError("remote sandbox migration is not implemented")

    blob = checkpoint(sandbox, key)
    return restore(blob, key)


__all__ = ["migrate"]
