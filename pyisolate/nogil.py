"""No-GIL readiness checks for PyIsolate runtime and extensions."""

from __future__ import annotations

import importlib.machinery
import os
import sys
import sysconfig
import warnings
from pathlib import Path
from types import ModuleType
from typing import Any

_NATIVE_SUFFIXES = tuple(importlib.machinery.EXTENSION_SUFFIXES)
_SAFE_ENV = "PYISOLATE_NOGIL_SAFE_MODULES"
_WARN_ENV = "PYISOLATE_WARN_UNSAFE_NOGIL_EXTENSIONS"


def is_no_gil_build() -> bool:
    """Return whether this interpreter was built with CPython's free-threaded ABI."""

    return bool(sysconfig.get_config_var("Py_GIL_DISABLED"))


def is_gil_enabled() -> bool | None:
    """Return effective process GIL state when CPython exposes it.

    Python 3.13+ free-threaded builds expose ``sys._is_gil_enabled``. Older
    interpreters cannot report this distinction, so ``None`` means unknown.
    """

    checker = getattr(sys, "_is_gil_enabled", None)
    if checker is None:
        return None
    return bool(checker())


def _configured_safe_roots() -> set[str]:
    raw = os.environ.get(_SAFE_ENV, "")
    return {item.strip().split(".", 1)[0] for item in raw.split(",") if item.strip()}


def _module_origin(module: ModuleType) -> str | None:
    spec = getattr(module, "__spec__", None)
    origin = getattr(spec, "origin", None)
    if origin:
        return origin
    filename = getattr(module, "__file__", None)
    return str(filename) if filename else None


def _is_native_origin(origin: str | None) -> bool:
    return origin is not None and origin.endswith(_NATIVE_SUFFIXES)


def imported_native_extensions() -> list[dict[str, Any]]:
    """Return imported native extension modules with no-GIL audit status.

    CPython does not expose a portable per-module flag that says whether an
    already imported extension declared ``Py_MOD_GIL_NOT_USED``. PyIsolate
    therefore treats native modules as unknown unless the deployment marks the
    root module in ``PYISOLATE_NOGIL_SAFE_MODULES``.
    """

    safe_roots = _configured_safe_roots()
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for name, module in sorted(sys.modules.items()):
        if not isinstance(module, ModuleType):
            continue
        origin = _module_origin(module)
        if not _is_native_origin(origin):
            continue
        assert origin is not None
        root = name.split(".", 1)[0]
        key = (name, origin)
        if key in seen:
            continue
        seen.add(key)
        marked_safe = root in safe_roots or name in safe_roots
        records.append(
            {
                "name": name,
                "root": root,
                "origin": str(Path(origin)),
                "suffix": next(
                    (suffix for suffix in _NATIVE_SUFFIXES if origin.endswith(suffix)),
                    Path(origin).suffix,
                ),
                "no_gil_safe": marked_safe,
                "status": "declared-safe" if marked_safe else "unknown",
                "reason": "declared in PYISOLATE_NOGIL_SAFE_MODULES"
                if marked_safe
                else "native extension has no PyIsolate no-GIL safety declaration",
            }
        )
    return records


def no_gil_readiness_report() -> dict[str, Any]:
    """Return the hard no-GIL axis used to classify runtime behavior."""

    no_gil_build = is_no_gil_build()
    gil_enabled = is_gil_enabled()
    extensions = imported_native_extensions()
    unknown_extensions = [item for item in extensions if not item["no_gil_safe"]]

    parallel_cells_ready = (
        bool(no_gil_build) and gil_enabled is not True and not unknown_extensions
    )
    if parallel_cells_ready:
        mode = "parallel_cells"
        reason = "free-threaded runtime with no unknown native extensions loaded"
    elif not no_gil_build:
        mode = "scheduled_compartments"
        reason = "Python was not built with --disable-gil"
    elif gil_enabled is True:
        mode = "scheduled_compartments"
        reason = "the process GIL is currently enabled"
    else:
        mode = "scheduled_compartments"
        reason = "native extension no-GIL safety is unknown"

    return {
        "build": {
            "py_gil_disabled": no_gil_build,
            "free_threaded_abi": no_gil_build,
            "soabi": sysconfig.get_config_var("SOABI"),
            "cache_tag": sys.implementation.cache_tag,
        },
        "runtime": {
            "gil_enabled": gil_enabled,
            "gil_state_known": gil_enabled is not None,
        },
        "extensions": {
            "loaded_native_count": len(extensions),
            "unknown_or_unmarked_count": len(unknown_extensions),
            "safe_declaration_env": _SAFE_ENV,
            "items": extensions,
        },
        "axis": {
            "mode": mode,
            "parallel_cells_ready": parallel_cells_ready,
            "scheduled_compartments": not parallel_cells_ready,
            "reason": reason,
        },
    }


def warn_if_unsafe_native_extensions() -> None:
    """Warn on free-threaded builds when native modules block parallel-cell claims."""

    if os.environ.get(_WARN_ENV, "1").lower() in {"0", "false", "no"}:
        return
    if not is_no_gil_build():
        return
    report = no_gil_readiness_report()
    unknown = report["extensions"]["unknown_or_unmarked_count"]
    if unknown:
        warnings.warn(
            f"PyIsolate is running on a no-GIL build, but {unknown} imported native "
            "extension module(s) are not declared no-GIL-safe; treating sandboxes as "
            "scheduled compartments rather than parallel cells. Set "
            f"{_SAFE_ENV}=module1,module2 only after auditing upstream no-GIL support.",
            RuntimeWarning,
            stacklevel=2,
        )
