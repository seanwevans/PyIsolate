"""Encrypted checkpoint helpers using JSON serialization.

State snapshots are encoded as JSON and sealed with ChaCha20‑Poly1305.
Keys must be exactly 32 bytes long.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .supervisor import Sandbox, spawn

_MAGIC = b"PYISOCP1"
_NONCE_LEN = 12
_LEN_SIZE = 4


def _encode_envelope(blob: bytes) -> bytes:
    return _MAGIC + len(blob).to_bytes(_LEN_SIZE, "big") + blob


def _decode_envelope(payload: bytes) -> bytes:
    header_len = len(_MAGIC) + _LEN_SIZE
    if len(payload) < header_len:
        raise ValueError("invalid checkpoint envelope")
    if payload[: len(_MAGIC)] != _MAGIC:
        raise ValueError("invalid checkpoint envelope")
    expected = int.from_bytes(payload[len(_MAGIC) : header_len], "big")
    body = payload[header_len:]
    if expected != len(body):
        raise ValueError("invalid checkpoint envelope length")
    if len(body) < _NONCE_LEN:
        raise ValueError("invalid checkpoint envelope length")
    return body


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
        nonce = os.urandom(_NONCE_LEN)
        blob = nonce + aead.encrypt(nonce, data, b"")
        return _encode_envelope(blob)
    finally:
        sandbox.close()


def restore(blob: bytes, key: bytes) -> Sandbox:
    """Decrypt *blob* with *key* and spawn a new sandbox."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    sealed = _decode_envelope(blob)
    nonce, ct = sealed[:_NONCE_LEN], sealed[_NONCE_LEN:]
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
        capabilities=state.get("capabilities"),
    )


__all__ = ["checkpoint", "restore"]
