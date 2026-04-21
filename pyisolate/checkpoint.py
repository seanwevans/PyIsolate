"""Encrypted checkpoint helpers using JSON serialization.

State snapshots are encoded as JSON and sealed with ChaCha20‑Poly1305.
Keys must be exactly 32 bytes long.
"""

from __future__ import annotations

import json
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .supervisor import Sandbox, spawn

_MAGIC = b"PYISOCP1"
_LEN_STRUCT = struct.Struct("!I")


def checkpoint(sandbox: Sandbox, key: bytes) -> bytes:
    """Serialize *sandbox* state and encrypt it with *key*.

    The sandbox is closed after its state is captured.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    state = sandbox.snapshot()
    try:
        try:
            data = json.dumps(state).encode("utf-8")
        except (TypeError, ValueError) as exc:  # json raises ValueError on NaN
            raise ValueError("sandbox state is not JSON serializable") from exc
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        encrypted = nonce + aead.encrypt(nonce, data, b"")
        blob = _MAGIC + _LEN_STRUCT.pack(len(encrypted)) + encrypted
        return blob
    finally:
        sandbox.close()


def restore(blob: bytes, key: bytes) -> Sandbox:
    """Decrypt *blob* with *key* and spawn a new sandbox."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(blob) < len(_MAGIC) + _LEN_STRUCT.size:
        raise ValueError("invalid checkpoint envelope")
    if blob[: len(_MAGIC)] != _MAGIC:
        raise ValueError("invalid checkpoint envelope")
    expected_len = _LEN_STRUCT.unpack_from(blob, len(_MAGIC))[0]
    encrypted = blob[len(_MAGIC) + _LEN_STRUCT.size :]
    if expected_len != len(encrypted):
        raise ValueError("invalid checkpoint envelope")
    if len(encrypted) < 12:
        raise ValueError("invalid checkpoint data")
    nonce, ct = encrypted[:12], encrypted[12:]
    aead = ChaCha20Poly1305(key)
    data = aead.decrypt(nonce, ct, b"")
    try:
        state = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid checkpoint data") from exc
    if not isinstance(state, dict):
        raise ValueError("invalid checkpoint payload: expected JSON object")
    name = state.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError(
            "invalid checkpoint payload: 'name' must be a non-empty string"
        )
    return spawn(
        name,
        policy=state.get("policy"),
        cpu_ms=state.get("cpu_ms"),
        mem_bytes=state.get("mem_bytes"),
        allowed_imports=state.get("allowed_imports"),
        numa_node=state.get("numa_node"),
    )


__all__ = ["checkpoint", "restore"]
