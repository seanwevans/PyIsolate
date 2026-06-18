"""Encrypted checkpoint helpers using JSON serialization.

State snapshots are encoded as JSON and sealed with ChaCha20‑Poly1305.
Keys must be exactly 32 bytes long.
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .runtime.thread import deserialize_capabilities
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


def _require_optional_positive_int(state: dict, field: str) -> int | None:
    value = state.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(
            f"invalid checkpoint payload: {field!r} must be None or a positive integer"
        )
    return value


def _require_optional_numa_node(state: dict) -> int | None:
    value = state.get("numa_node")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(
            "invalid checkpoint payload: 'numa_node' must be None or a non-negative integer"
        )
    return value


def _require_optional_allowed_imports(state: dict) -> list[str] | None:
    value = state.get("allowed_imports")
    if value is None:
        return None
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(
            "invalid checkpoint payload: 'allowed_imports' must be None or a list of non-empty strings"
        )
    return value


def _is_str_list(value: object, *, allow_empty_items: bool = False) -> bool:
    return isinstance(value, list) and all(
        isinstance(item, str) and (allow_empty_items or bool(item)) for item in value
    )


def _validate_serialized_capability(capability: object) -> None:
    if isinstance(capability, list):
        for item in capability:
            _validate_serialized_capability(item)
        return
    if not isinstance(capability, dict):
        raise ValueError("capability must be a serialized mapping")

    kind = capability.get("__pyisolate_capability__")
    if kind == "filesystem":
        if not _is_str_list(capability.get("roots")):
            raise ValueError("filesystem capability roots must be strings")
    elif kind == "network":
        if not _is_str_list(capability.get("destinations")):
            raise ValueError("network capability destinations must be strings")
    elif kind == "secrets":
        values = capability.get("values")
        if not isinstance(values, dict):
            raise ValueError("secrets capability values must be a mapping")
        for key, value in values.items():
            if not isinstance(key, str) or not key or not isinstance(value, str):
                raise ValueError("secrets capability values must be hex strings")
            bytes.fromhex(value)
    elif kind == "subprocess":
        if not _is_str_list(capability.get("allowed_commands")):
            raise ValueError("subprocess capability commands must be strings")
        if not isinstance(capability.get("allow_shell", False), bool):
            raise ValueError("subprocess capability allow_shell must be boolean")
    elif kind in {"read_path", "write_path"}:
        path = capability.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("path capability path must be a non-empty string")
    elif kind == "connect_tcp":
        host = capability.get("host")
        port = capability.get("port")
        if not isinstance(host, str) or not host:
            raise ValueError("connect_tcp capability host must be a non-empty string")
        if isinstance(port, bool) or not isinstance(port, int) or port <= 0:
            raise ValueError("connect_tcp capability port must be a positive integer")
    elif kind == "import":
        module = capability.get("module")
        if not isinstance(module, str) or not module:
            raise ValueError("import capability module must be a non-empty string")
    elif kind == "cpu_budget":
        ms = capability.get("ms")
        if isinstance(ms, bool) or not isinstance(ms, int) or ms <= 0:
            raise ValueError("cpu_budget capability ms must be a positive integer")
    elif kind not in {"clock", "random"}:
        raise ValueError("unknown serialized capability kind")


def _require_optional_capabilities(state: dict) -> dict | None:
    value = state.get("capabilities")
    if value is None:
        return None
    if not isinstance(value, dict) or any(
        not isinstance(name, str) or not name for name in value
    ):
        raise ValueError(
            "invalid checkpoint payload: 'capabilities' must be None or a serialized capability mapping"
        )
    try:
        for capability in value.values():
            _validate_serialized_capability(capability)
        deserialize_capabilities(value)
    except (TypeError, ValueError, KeyError) as exc:
        raise ValueError(
            "invalid checkpoint payload: 'capabilities' must be None or a serialized capability mapping"
        ) from exc
    return value


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
    cpu_ms = _require_optional_positive_int(state, "cpu_ms")
    mem_bytes = _require_optional_positive_int(state, "mem_bytes")
    allowed_imports = _require_optional_allowed_imports(state)
    numa_node = _require_optional_numa_node(state)
    capabilities = _require_optional_capabilities(state)
    return spawn(
        name,
        policy=state.get("policy"),
        cpu_ms=cpu_ms,
        mem_bytes=mem_bytes,
        allowed_imports=allowed_imports,
        numa_node=numa_node,
        capabilities=capabilities,
    )


__all__ = ["checkpoint", "restore"]
