"""Tests for the ``backend="process"`` real process-boundary isolation mode."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso

# The object-graph escape that fully defeats the sub-interpreter backend:
# recover the *real* __import__ from a stdlib module's globals, bypassing the
# guarded builtins and the import allow-list entirely.
_ESCAPE_TO_OS = """
for cls in ().__class__.__base__.__subclasses__():
    if cls.__name__ == "catch_warnings":
        real_import = cls()._module.__builtins__["__import__"]
        _os = real_import("os")
        post(_os.getpid())
        break
"""


def test_process_backend_roundtrip():
    with iso.spawn("proc-rt", allowed_imports=["math"], backend="process") as sb:
        sb.exec("from math import sqrt; post(sqrt(2))")
        assert sb.recv(timeout=5) == pytest.approx(2**0.5)


def test_process_backend_reports_its_backend():
    with iso.spawn("proc-b", backend="process") as sb:
        assert sb.backend == "process"


def test_process_backend_runs_in_a_separate_process():
    with iso.spawn("proc-pid", allowed_imports=["os"], backend="process") as sb:
        sb.exec("import os; post(os.getpid())")
        child_pid = sb.recv(timeout=5)
    assert isinstance(child_pid, int)
    assert child_pid != os.getpid()


def test_process_backend_import_allowlist_denies_unlisted_module():
    with iso.spawn("proc-deny", allowed_imports=["math"], backend="process") as sb:
        sb.exec("import os")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=5)


def test_object_graph_escape_is_confined_to_the_child_process():
    # The escape still *runs* -- a process boundary does not stop in-process
    # Python tricks -- but it can only reach os inside its own process, never
    # the supervisor's address space. That is the whole point of the boundary.
    with iso.spawn("proc-escape", allowed_imports=["math"], backend="process") as sb:
        sb.exec(_ESCAPE_TO_OS)
        escaped_pid = sb.recv(timeout=5)
    assert isinstance(escaped_pid, int)
    assert escaped_pid != os.getpid()


def test_process_backend_surfaces_guest_exceptions():
    with iso.spawn("proc-err", allowed_imports=["math"], backend="process") as sb:
        sb.exec("raise ValueError('boom')")
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)


def test_process_backend_non_json_result_is_rejected():
    with iso.spawn("proc-json", backend="process") as sb:
        sb.exec("post(object())")
        with pytest.raises(iso.SandboxError):
            sb.recv(timeout=5)


def test_process_backend_call_returns_result():
    with iso.spawn("proc-call", allowed_imports=["math"], backend="process") as sb:
        assert sb.call("math.gcd", 12, 18, timeout=5) == 6


def test_close_terminates_the_child_process():
    sb = iso.spawn("proc-close", allowed_imports=["os"], backend="process")
    sb.exec("import os; post(os.getpid())")
    child_pid = sb.recv(timeout=5)
    sb.close()
    # After close the child is gone; signalling pid 0 group would be unsafe, so
    # assert the specific pid no longer exists.
    with pytest.raises(OSError):
        os.kill(child_pid, 0)


def test_process_sandbox_appears_in_list_active():
    with iso.spawn("proc-list", backend="process"):
        active = iso.list_active()
        assert "proc-list" in active
        assert active["proc-list"].backend == "process"
    assert "proc-list" not in iso.list_active()


def test_process_backend_tracks_operations_in_stats():
    with iso.spawn("proc-stats", allowed_imports=["math"], backend="process") as sb:
        sb.exec("post(1)")
        sb.recv(timeout=5)
        sb.exec("post(2)")
        sb.recv(timeout=5)
        assert sb.stats.operations == 2
        assert sb.stats.errors == 0


def test_process_backend_unsupported_features_raise_not_implemented():
    with iso.spawn("proc-unsup", backend="process") as sb:
        with pytest.raises(NotImplementedError):
            sb.enable_tracing()
        with pytest.raises(NotImplementedError):
            sb.snapshot()


def test_microvm_backend_remains_unimplemented():
    with pytest.raises(RuntimeError):
        iso.spawn("proc-vm", backend="microvm")
