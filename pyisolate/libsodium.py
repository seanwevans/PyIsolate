"""Thin wrapper around libsodium constant-time helpers."""

from __future__ import annotations

import hmac

try:
    from nacl.bindings import sodium_memcmp as _sodium_memcmp  # type: ignore

    def constant_compare(a: bytes, b: bytes) -> bool:
        """Return ``True`` if ``a`` equals ``b`` using ``sodium_memcmp``."""
        if len(a) != len(b):
            return False
        return _sodium_memcmp(a, b)

except Exception:  # pragma: no cover - fallback when PyNaCl/libsodium missing

    def constant_compare(a: bytes, b: bytes) -> bool:
        """Fallback to ``hmac.compare_digest`` if libsodium is unavailable."""
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)
