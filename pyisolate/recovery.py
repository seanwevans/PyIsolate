"""Durable supervisor recovery helpers.

The supervisor persists lightweight sandbox metadata to allow restart-time cleanup
of leaked resources (cgroups, temp directories) after crashes.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_STATE_ROOT = Path(
    os.environ.get("PYISOLATE_STATE_ROOT", Path(tempfile.gettempdir()) / "pyisolate")
)
_REGISTRY_PATH = Path(
    os.environ.get("PYISOLATE_REGISTRY_PATH", _STATE_ROOT / "supervisor_registry.json")
)
_TEMP_ROOT = Path(os.environ.get("PYISOLATE_TEMP_ROOT", _STATE_ROOT / "sandboxes"))



def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)



def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, sort_keys=True)
        fh.flush()
        os.fsync(fh.fileno())
    tmp.replace(path)



def _read_registry() -> dict[str, dict[str, Any]]:
    if not _REGISTRY_PATH.exists():
        return {}
    try:
        data = json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        log.warning("failed to read recovery registry %s: %s", _REGISTRY_PATH, exc)
        return {}

    if not isinstance(data, dict):
        log.warning("invalid recovery registry format in %s", _REGISTRY_PATH)
        return {}

    sandboxes = data.get("sandboxes", {})
    if not isinstance(sandboxes, dict):
        log.warning("invalid sandboxes map in recovery registry %s", _REGISTRY_PATH)
        return {}

    result: dict[str, dict[str, Any]] = {}
    for name, meta in sandboxes.items():
        if isinstance(name, str) and isinstance(meta, dict):
            result[name] = dict(meta)
    return result



def _write_registry(sandboxes: dict[str, dict[str, Any]]) -> None:
    _atomic_write_json(_REGISTRY_PATH, {"sandboxes": sandboxes})



def recover() -> dict[str, dict[str, Any]]:
    """Load persisted sandbox metadata.

    Corrupt registries are tolerated and reset to an empty map.
    """

    sandboxes = _read_registry()
    if not sandboxes and _REGISTRY_PATH.exists():
        # Normalize a corrupt/invalid registry to empty valid JSON.
        _write_registry({})
    return sandboxes



def update_sandbox(name: str, meta: dict[str, Any]) -> None:
    sandboxes = _read_registry()
    sandboxes[name] = dict(meta)
    _write_registry(sandboxes)



def drop_sandbox(name: str) -> None:
    sandboxes = _read_registry()
    sandboxes.pop(name, None)
    _write_registry(sandboxes)



def allocate_temp_dir(name: str) -> Path:
    """Allocate a deterministic per-sandbox temp directory."""

    path = _TEMP_ROOT / name
    path.mkdir(parents=True, exist_ok=True)
    return path



def cleanup_temp_dir(path_or_name: str | Path) -> None:
    """Remove a sandbox temp directory if it exists."""

    if isinstance(path_or_name, Path):
        path = path_or_name
    else:
        path = _TEMP_ROOT / path_or_name
    shutil.rmtree(path, ignore_errors=True)



def cleanup_temp_orphans(active_names: set[str]) -> list[Path]:
    """Remove temp directories that do not belong to active sandboxes."""

    removed: list[Path] = []
    if not _TEMP_ROOT.exists():
        return removed
    for child in _TEMP_ROOT.iterdir():
        if not child.is_dir():
            continue
        if child.name in active_names:
            continue
        cleanup_temp_dir(child)
        removed.append(child)
    return removed
