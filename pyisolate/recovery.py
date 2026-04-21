"""Crash-only recovery helpers for supervisor state."""

from __future__ import annotations

import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from . import cgroup

log = logging.getLogger(__name__)

STATE_DIR = Path(tempfile.gettempdir()) / "pyisolate-state"
REGISTRY_FILE = STATE_DIR / "supervisor_registry.json"
TEMP_ROOT = STATE_DIR / "sandboxes"


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def load_registry() -> dict[str, Any]:
    """Load persisted supervisor state, returning an empty registry on failure."""
    try:
        raw = REGISTRY_FILE.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {"sandboxes": {}}
    if not isinstance(data, dict):
        return {"sandboxes": {}}
    sandboxes = data.get("sandboxes")
    if not isinstance(sandboxes, dict):
        return {"sandboxes": {}}
    return {"sandboxes": sandboxes}


def save_registry(registry: dict[str, Any]) -> None:
    _atomic_write_json(REGISTRY_FILE, registry)


def update_sandbox(name: str, data: dict[str, Any]) -> None:
    registry = load_registry()
    sandboxes = registry.setdefault("sandboxes", {})
    sandboxes[name] = data
    save_registry(registry)


def drop_sandbox(name: str) -> None:
    registry = load_registry()
    sandboxes = registry.get("sandboxes", {})
    if name in sandboxes:
        del sandboxes[name]
        save_registry(registry)


def allocate_temp_dir(name: str) -> Path:
    """Create a deterministic per-sandbox temp directory."""
    path = TEMP_ROOT / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def delete_temp_dir(path: Path | None) -> None:
    if path is None:
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception as exc:
        log.warning("Failed to delete temp dir %s: %s", path, exc)


def recover(active_names: set[str]) -> None:
    """Recover state after supervisor restart and cleanup orphans."""
    registry = load_registry()
    sandboxes = registry.get("sandboxes", {})
    stale_names = {name for name in sandboxes if name not in active_names}

    for name in stale_names:
        entry = sandboxes.get(name, {})
        temp_dir = entry.get("temp_dir")
        if isinstance(temp_dir, str):
            delete_temp_dir(Path(temp_dir))

    cgroup.cleanup_orphans(active_names)
    if TEMP_ROOT.exists():
        for path in TEMP_ROOT.iterdir():
            if path.is_dir() and path.name not in active_names:
                delete_temp_dir(path)

    if stale_names:
        for name in stale_names:
            sandboxes.pop(name, None)
        save_registry(registry)
