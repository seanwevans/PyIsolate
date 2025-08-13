"""Encrypted checkpoint helpers."""

from __future__ import annotations

import os
import pickle

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .supervisor import Sandbox, spawn


def checkpoint(sandbox: Sandbox, key: bytes) -> bytes:
    """Serialize *sandbox* state and encrypt it with *key*.

    The sandbox is closed after its state is captured.
    """
    state = sandbox.snapshot()
    data = pickle.dumps(state)
    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    blob = nonce + aead.encrypt(nonce, data, b"")
    sandbox.close()
    return blob


def restore(blob: bytes, key: bytes) -> Sandbox:
    """Decrypt *blob* with *key* and spawn a new sandbox."""
    nonce, ct = blob[:12], blob[12:]
    aead = ChaCha20Poly1305(key)
    data = aead.decrypt(nonce, ct, b"")
    state = pickle.loads(data)
    return spawn(
        state["name"],
        policy=state.get("policy"),
        cpu_ms=state.get("cpu_ms"),
        mem_bytes=state.get("mem_bytes"),
    )


__all__ = ["checkpoint", "restore"]
