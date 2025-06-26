"""Sandbox migration utilities."""

from __future__ import annotations

from .checkpoint import checkpoint, restore
from .supervisor import Sandbox


def migrate(sandbox: Sandbox, host: str, key: bytes) -> Sandbox:
    """Migrate *sandbox* to *host* using an encrypted checkpoint.

    This stub simply checkpoints and restores locally.
    """
    blob = checkpoint(sandbox, key)
    # Real implementation would send *blob* to *host* securely
    return restore(blob, key)


__all__ = ["migrate"]
