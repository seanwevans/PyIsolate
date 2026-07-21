"""Tests for the no-GIL readiness axis (:mod:`pyisolate.nogil`).

The no-GIL axis is a release gate: it decides whether a host may claim
parallel-cell semantics or must fall back to scheduled compartments. The suite
usually runs on a GIL-enabled interpreter, so the axis logic is exercised by
monkeypatching the three inputs (build flag, runtime GIL state, loaded native
extensions) rather than depending on the host being a free-threaded build.
"""

import importlib.machinery
import sys
import sysconfig
import warnings
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

from pyisolate import nogil


def _fake_native_module(name: str) -> ModuleType:
    """Build a module object that looks like an imported native extension."""
    suffix = importlib.machinery.EXTENSION_SUFFIXES[0]
    origin = f"/nonexistent/{name}{suffix}"
    module = ModuleType(name)
    module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None, origin=origin)
    module.__file__ = origin
    return module


# -- primitive probes -------------------------------------------------------


def test_is_no_gil_build_matches_sysconfig():
    assert nogil.is_no_gil_build() == bool(sysconfig.get_config_var("Py_GIL_DISABLED"))


def test_is_gil_enabled_matches_interpreter():
    checker = getattr(sys, "_is_gil_enabled", None)
    if checker is None:
        assert nogil.is_gil_enabled() is None
    else:
        assert nogil.is_gil_enabled() == bool(checker())


def test_configured_safe_roots_parses_and_normalizes(monkeypatch):
    monkeypatch.setenv(nogil._SAFE_ENV, " numpy , pandas.core ,, torch ")
    # Whitespace is stripped, empty entries dropped, and dotted names collapse
    # to their root module so a whole package can be marked in one entry.
    assert nogil._configured_safe_roots() == {"numpy", "pandas", "torch"}


def test_configured_safe_roots_empty_when_unset(monkeypatch):
    monkeypatch.delenv(nogil._SAFE_ENV, raising=False)
    assert nogil._configured_safe_roots() == set()


# -- native extension inventory --------------------------------------------


def test_imported_native_extensions_flags_unknown(monkeypatch):
    monkeypatch.delenv(nogil._SAFE_ENV, raising=False)
    monkeypatch.setitem(sys.modules, "fakenative", _fake_native_module("fakenative"))
    records = {item["name"]: item for item in nogil.imported_native_extensions()}
    assert "fakenative" in records
    record = records["fakenative"]
    assert record["no_gil_safe"] is False
    assert record["status"] == "unknown"


def test_imported_native_extensions_honors_safe_declaration(monkeypatch):
    monkeypatch.setenv(nogil._SAFE_ENV, "fakenative")
    monkeypatch.setitem(sys.modules, "fakenative", _fake_native_module("fakenative"))
    records = {item["name"]: item for item in nogil.imported_native_extensions()}
    assert records["fakenative"]["no_gil_safe"] is True
    assert records["fakenative"]["status"] == "declared-safe"


def test_pure_python_modules_are_not_reported_as_native(monkeypatch):
    pure = ModuleType("purepy")
    pure.__spec__ = importlib.machinery.ModuleSpec(
        "purepy", loader=None, origin="/nonexistent/purepy.py"
    )
    pure.__file__ = "/nonexistent/purepy.py"
    monkeypatch.setitem(sys.modules, "purepy", pure)
    names = {item["name"] for item in nogil.imported_native_extensions()}
    assert "purepy" not in names


# -- the readiness axis -----------------------------------------------------


def _force(monkeypatch, *, build, gil, unknown_ext):
    monkeypatch.setattr(nogil, "is_no_gil_build", lambda: build)
    monkeypatch.setattr(nogil, "is_gil_enabled", lambda: gil)
    ext = [_fake_native_module("x")] if unknown_ext else []
    records = [{"name": "x", "no_gil_safe": False, "status": "unknown"} for _ in ext]
    monkeypatch.setattr(nogil, "imported_native_extensions", lambda: records)


def test_axis_parallel_cells_when_free_threaded_and_clean(monkeypatch):
    _force(monkeypatch, build=True, gil=False, unknown_ext=False)
    report = nogil.no_gil_readiness_report()
    assert report["axis"]["mode"] == "parallel_cells"
    assert report["axis"]["parallel_cells_ready"] is True
    assert report["axis"]["scheduled_compartments"] is False


def test_axis_scheduled_when_not_a_no_gil_build(monkeypatch):
    _force(monkeypatch, build=False, gil=None, unknown_ext=False)
    report = nogil.no_gil_readiness_report()
    assert report["axis"]["mode"] == "scheduled_compartments"
    assert "--disable-gil" in report["axis"]["reason"]


def test_axis_scheduled_when_process_gil_enabled(monkeypatch):
    _force(monkeypatch, build=True, gil=True, unknown_ext=False)
    report = nogil.no_gil_readiness_report()
    assert report["axis"]["mode"] == "scheduled_compartments"
    assert report["axis"]["parallel_cells_ready"] is False
    assert "GIL" in report["axis"]["reason"]


def test_axis_scheduled_when_native_extension_unknown(monkeypatch):
    _force(monkeypatch, build=True, gil=False, unknown_ext=True)
    report = nogil.no_gil_readiness_report()
    assert report["axis"]["mode"] == "scheduled_compartments"
    assert report["extensions"]["unknown_or_unmarked_count"] == 1
    assert "native extension" in report["axis"]["reason"]


def test_report_shape_is_stable(monkeypatch):
    _force(monkeypatch, build=True, gil=False, unknown_ext=False)
    report = nogil.no_gil_readiness_report()
    assert set(report) == {"build", "runtime", "extensions", "axis"}
    assert report["extensions"]["safe_declaration_env"] == nogil._SAFE_ENV
    assert report["build"]["py_gil_disabled"] is True


# -- the free-threaded warning ---------------------------------------------


def test_warn_is_silent_on_a_gil_build(monkeypatch):
    monkeypatch.setattr(nogil, "is_no_gil_build", lambda: False)
    monkeypatch.delenv(nogil._WARN_ENV, raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        nogil.warn_if_unsafe_native_extensions()  # must not raise


def test_warn_fires_for_unknown_extensions_on_free_threaded_build(monkeypatch):
    monkeypatch.setattr(nogil, "is_no_gil_build", lambda: True)
    monkeypatch.delenv(nogil._WARN_ENV, raising=False)
    monkeypatch.setattr(
        nogil,
        "no_gil_readiness_report",
        lambda: {"extensions": {"unknown_or_unmarked_count": 2}},
    )
    with pytest.warns(RuntimeWarning, match="not declared no-GIL-safe"):
        nogil.warn_if_unsafe_native_extensions()


def test_warn_is_silent_when_no_unknown_extensions(monkeypatch):
    monkeypatch.setattr(nogil, "is_no_gil_build", lambda: True)
    monkeypatch.delenv(nogil._WARN_ENV, raising=False)
    monkeypatch.setattr(
        nogil,
        "no_gil_readiness_report",
        lambda: {"extensions": {"unknown_or_unmarked_count": 0}},
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        nogil.warn_if_unsafe_native_extensions()


def test_warn_can_be_disabled_by_env(monkeypatch):
    monkeypatch.setattr(nogil, "is_no_gil_build", lambda: True)
    monkeypatch.setenv(nogil._WARN_ENV, "0")

    def _boom():  # pragma: no cover - must never be called when disabled
        raise AssertionError("readiness report computed despite disabled warning")

    monkeypatch.setattr(nogil, "no_gil_readiness_report", _boom)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        nogil.warn_if_unsafe_native_extensions()
