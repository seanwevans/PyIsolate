"""Tests for the real sub-interpreter cell backend.

Two groups. The first needs CPython 3.14+ and exercises actual interpreters;
the second runs everywhere and covers the parts that decide behaviour without
one -- the fail-closed path, the spec, and the pool's bookkeeping -- so the
3.11-3.13 matrix still gets coverage of the logic it can reach.
"""

import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from pyisolate import errors
from pyisolate.runtime import subinterpreter as S

ROOT = Path(__file__).resolve().parents[1]

requires_interpreters = pytest.mark.skipif(
    not S.is_available(),
    reason=f"needs CPython {S.MIN_PYTHON[0]}.{S.MIN_PYTHON[1]}+ for concurrent.interpreters",
)


# --- availability ---------------------------------------------------------


def test_min_python_is_the_public_api_not_the_private_one():
    """3.12/3.13's _interpreters heap-corrupts on realistic import surfaces."""
    assert S.MIN_PYTHON == (3, 14)


def test_is_available_tracks_the_running_build():
    expected = sys.version_info[:2] >= S.MIN_PYTHON
    assert S.is_available() is expected


@pytest.mark.skipif(S.is_available(), reason="this build has sub-interpreters")
def test_fails_closed_rather_than_degrading_to_a_thread():
    """Substituting a different isolation model silently is the whole problem."""
    with pytest.raises(errors.SandboxError) as excinfo:
        S.require_available()
    message = str(excinfo.value)
    assert "3.14" in message
    assert "backend='thread'" in message
    assert "backend='process'" in message


# --- CellSpec (no interpreter needed) -------------------------------------


def test_spec_preimports_everything_allowed_by_default():
    spec = S.CellSpec.build(["json", "math"])
    assert spec.allowed_imports == frozenset({"json", "math"})
    assert spec.preimport == ("json", "math")


def test_spec_rejects_preimporting_a_module_policy_forbids():
    with pytest.raises(ValueError, match="not in allowed_imports"):
        S.CellSpec(allowed_imports=frozenset({"math"}), preimport=("os",))


def test_spec_allows_parents_of_allowed_submodules():
    """``import a.b`` imports ``a`` first, so the parent has to resolve."""
    spec = S.CellSpec.build(["email.message"])
    assert spec.allows("email.message")
    assert spec.allows("email")
    assert not spec.allows("os")
    assert not spec.allows("emailx")


def test_spec_is_hashable_so_the_pool_can_key_on_it():
    a = S.CellSpec.build(["json"])
    b = S.CellSpec.build(["json"])
    c = S.CellSpec.build(["json", "math"])
    assert a == b and hash(a) == hash(b)
    assert len({a, b, c}) == 2


def test_runtime_imports_are_allowed_so_the_queue_can_work():
    """Blocking these breaks CPython's own machinery, not the guest."""
    assert "pickle" in S._RUNTIME_IMPORTS
    assert "traceback" in S._RUNTIME_IMPORTS


# --- pool bookkeeping -----------------------------------------------------


def test_pool_rejects_nonsense_sizes():
    with pytest.raises(ValueError):
        S.CellPool(warm_per_spec=-1)
    with pytest.raises(ValueError):
        S.CellPool(max_warm=-1)


@requires_interpreters
def test_pool_reuses_a_warm_cell_instead_of_creating_one():
    with S.CellPool(warm_per_spec=0) as pool:
        spec = S.CellSpec.build(["math"])
        assert pool.prewarm(spec, 2) == 2
        assert pool.stats()["warm"] == 2

        first = pool.acquire(spec)
        assert pool.stats()["reused"] == 1
        assert pool.stats()["warm"] == 1
        first.retire()


@requires_interpreters
def test_pool_creates_on_a_miss():
    with S.CellPool(warm_per_spec=0) as pool:
        cell = pool.acquire(S.CellSpec.build(["math"]))
        stats = pool.stats()
        assert stats["created"] == 1
        assert stats["reused"] == 0
        cell.retire()


@requires_interpreters
def test_a_warm_cell_is_not_handed_to_a_different_spec():
    """A cell is only interchangeable with one warmed the same way."""
    with S.CellPool(warm_per_spec=0) as pool:
        warmed = S.CellSpec.build(["math"])
        other = S.CellSpec.build(["json"])
        pool.prewarm(warmed, 1)
        cell = pool.acquire(other)
        assert pool.stats()["reused"] == 0
        assert pool.stats()["created"] == 2
        cell.retire()


@requires_interpreters
def test_release_retires_rather_than_returning_to_the_pool():
    """There is no reset, so a used cell cannot be given to another tenant."""
    with S.CellPool(warm_per_spec=0) as pool:
        spec = S.CellSpec.build(["math"])
        cell = pool.acquire(spec)
        pool.release(cell)
        assert cell.state is S.CellState.RETIRED
        assert pool.stats()["retired"] == 1
        assert pool.stats()["warm"] == 0


@requires_interpreters
def test_acquire_after_close_is_refused():
    pool = S.CellPool(warm_per_spec=0)
    pool.close()
    with pytest.raises(errors.SandboxError, match="closed"):
        pool.acquire(S.CellSpec.build([]))


# --- the isolation the backend exists for ---------------------------------


@requires_interpreters
def test_cells_do_not_share_globals():
    spec = S.CellSpec.build(["math"])
    a, b = S.Cell(spec), S.Cell(spec)
    try:
        a.exec("leaked = 'from A'")
        with pytest.raises(Exception) as excinfo:
            b.exec("post(leaked)")
        assert "leaked" in str(excinfo.value)
    finally:
        a.retire()
        b.retire()


@requires_interpreters
def test_cells_do_not_share_sys_modules():
    """The actual difference from the thread backend."""
    spec = S.CellSpec.build(["json", "math"])
    a, b = S.Cell(spec), S.Cell(spec)
    try:
        a.exec("import json; json.MARKER = 'set by A'")
        b.exec("import json; post(hasattr(json, 'MARKER'))")
        assert b.drain() == [("post", False)]
    finally:
        a.retire()
        b.retire()


@requires_interpreters
def test_the_import_hook_does_not_touch_the_host_interpreter():
    import builtins

    before = builtins.__import__
    cell = S.Cell(S.CellSpec.build(["math"]))
    try:
        cell.exec("import math")
        assert builtins.__import__ is before
        # ...and the host can still import something the cell could not.
        import os  # noqa: F401
    finally:
        cell.retire()


@requires_interpreters
def test_denied_import_raises_inside_the_cell():
    cell = S.Cell(S.CellSpec.build(["math"]))
    try:
        with pytest.raises(Exception, match="not permitted by policy"):
            cell.exec("import os")
    finally:
        cell.retire()


@requires_interpreters
def test_allowed_import_works():
    cell = S.Cell(S.CellSpec.build(["math"]))
    try:
        cell.exec("from math import sqrt; post(sqrt(9))")
        assert cell.drain() == [("post", 3.0)]
    finally:
        cell.retire()


# --- the message contract -------------------------------------------------


@requires_interpreters
def test_messages_cross_as_json_so_the_supervisor_never_unpickles():
    """The queue pickles anything not natively shareable; a str is shareable."""
    cell = S.Cell(S.CellSpec.build([]))
    try:
        cell.exec("post({'a': [1, 2], 'b': None})")
        raw = cell._outbox.get_nowait()
        assert isinstance(raw, str)
        assert raw == '["post", {"a": [1, 2], "b": null}]'
    finally:
        cell.retire()


@requires_interpreters
def test_posting_something_unserialisable_fails_at_the_call():
    """A clear TypeError beats an opaque NotShareableError from the runtime."""
    cell = S.Cell(S.CellSpec.build([]))
    try:
        with pytest.raises(Exception) as excinfo:
            cell.exec("post(object())")
        assert "JSON serializable" in str(excinfo.value)
    finally:
        cell.retire()


@requires_interpreters
def test_log_metric_and_request_all_reach_the_supervisor():
    cell = S.Cell(S.CellSpec.build([]))
    try:
        cell.exec(
            "log('info', 'hello', k=1)\n"
            "metric('m', 3)\n"
            "request('read_path', '/tmp/x', mode='r')\n"
        )
        kinds = dict(cell.drain())
        assert kinds["log"] == {"level": "info", "message": "hello", "fields": {"k": 1}}
        assert kinds["metric"] == {"name": "m", "value": 3}
        assert kinds["request"] == {
            "capability": "read_path",
            "args": ["/tmp/x"],
            "kwargs": {"mode": "r"},
        }
    finally:
        cell.retire()


def test_malformed_cell_messages_are_dropped_not_propagated():
    """Guest code can reach the outbox, so the frame is validated not trusted."""
    assert S.Cell._decode("not json") is None
    assert S.Cell._decode(b"bytes") is None
    assert S.Cell._decode('{"not": "a list"}') is None
    assert S.Cell._decode('["one element"]') is None
    assert S.Cell._decode("[1, 2]") is None
    assert S.Cell._decode('["post", 42]') == ("post", 42)


# --- reclaim ---------------------------------------------------------------


@requires_interpreters
def test_a_retired_cell_cannot_be_reused():
    cell = S.Cell(S.CellSpec.build([]))
    assert cell.retire() is True
    with pytest.raises(errors.SandboxError, match="retired"):
        cell.exec("x = 1")


@requires_interpreters
def test_an_abandoned_cell_cannot_be_reused():
    cell = S.Cell(S.CellSpec.build([]))
    try:
        cell.abandon("test")
        assert cell.state is S.CellState.ABANDONED
        assert cell.is_usable() is False
        with pytest.raises(errors.SandboxError, match="abandoned"):
            cell.exec("x = 1")
    finally:
        cell.retire()


#: Scenarios below run in a *fresh* interpreter, not a fork.
#:
#: They strand a thread inside a spinning interpreter, which cannot be
#: reclaimed -- that is the thing being tested -- so running them in-process
#: would hang pytest at exit. ``os.fork()`` is not the answer either: forking a
#: process that already hosts sub-interpreters and their threads segfaults, as
#: it does when these tests follow others in the same session. A fresh process
#: is the only clean kill domain, which is the same conclusion a deployment
#: reaches: pre-fork the workers, then create cells inside them.
_CHILD_PREAMBLE = """
import sys, time
sys.path.insert(0, %r)
from pyisolate import errors
from pyisolate.runtime import subinterpreter as S
"""


def _run_in_fresh_process(
    body_source: str, timeout: float = 60.0
) -> subprocess.CompletedProcess:
    script = (_CHILD_PREAMBLE % str(ROOT)) + textwrap.dedent(body_source)
    return subprocess.run(
        [sys.executable, "-W", "ignore", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@requires_interpreters
def test_timeout_abandons_the_cell_and_says_so():
    """A running interpreter cannot be reclaimed, so do not claim it was.

    The spun-up thread stays pinned for the life of the process. That is the
    honest outcome, and the reason a deployment that must survive runaway
    guests needs a process-level kill domain.
    """
    result = _run_in_fresh_process(
        r"""
        pool = S.CellPool(warm_per_spec=0)
        sandbox = S.SubinterpreterSandbox(
            "runaway", pool=pool, spec=S.CellSpec.build([]), wall_time_ms=250
        )
        try:
            sandbox.exec("while True:\n    pass")
        except errors.WallTimeExceeded as exc:
            assert "abandoned" in str(exc), exc
        else:
            raise AssertionError("runaway exec returned")
        assert pool.stats()["abandoned"] == 1, pool.stats()
        assert sandbox.is_alive() is False
        # The pool stays usable for everyone else; only the one cell is lost.
        other = pool.acquire(S.CellSpec.build([]))
        other.exec("post(1)")
        assert other.drain() == [("post", 1)]
        other.retire()
        print("OK")
        # The stranded thread would otherwise keep this process alive.
        import os
        os._exit(0)
        """
    )
    assert "OK" in result.stdout, result.stderr
    assert result.returncode == 0, result.stderr


@requires_interpreters
def test_kill_reports_false_while_running_rather_than_lying():
    result = _run_in_fresh_process(
        r"""
        pool = S.CellPool(warm_per_spec=0)
        cell = pool.acquire(S.CellSpec.build([]))
        cell.exec_in_thread("while True:\n    pass")
        # Wait for the runtime to report the interpreter as executing, not
        # just for our own flag: exec_in_thread sets RUNNING before its thread
        # has entered the interpreter.
        deadline = time.monotonic() + 5.0
        while not cell._is_running() and time.monotonic() < deadline:
            time.sleep(0.005)
        assert cell._is_running(), cell.state
        assert cell.kill() is False
        assert cell.retire() is False
        assert cell.state is S.CellState.ABANDONED, cell.state
        print("OK")
        import os
        os._exit(0)
        """
    )
    assert "OK" in result.stdout, result.stderr
    assert result.returncode == 0, result.stderr


# --- the sandbox handle ---------------------------------------------------


@requires_interpreters
def test_sandbox_round_trip():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox(
            "demo", pool=pool, spec=S.CellSpec.build(["math"])
        )
        sandbox.exec("from math import sqrt; post(sqrt(2))")
        assert sandbox.recv() == pytest.approx(1.4142135623730951)
        assert sandbox.is_alive() is True
        sandbox.close()
        assert sandbox.is_alive() is False


@requires_interpreters
def test_sandbox_surfaces_broker_requests_for_the_supervisor():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        sandbox.exec("request('read_path', '/etc/hosts')")
        requests = sandbox.get_broker_requests()
        assert requests == [
            {"capability": "read_path", "args": ["/etc/hosts"], "kwargs": {}}
        ]
        sandbox.close()


@requires_interpreters
def test_sandbox_stats_expose_the_cell_and_the_pool():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        stats = sandbox.stats()
        assert stats["backend"] == "subinterpreter"
        assert isinstance(stats["cell_id"], int)
        assert stats["cell_state"] == "idle"
        assert stats["pool"]["created"] == 1
        sandbox.close()


@requires_interpreters
def test_recv_times_out_rather_than_blocking_forever():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        with pytest.raises(errors.TimeoutError):
            sandbox.recv(timeout=0.05)
        sandbox.close()


# --- the surface the Sandbox handle delegates to --------------------------


@requires_interpreters
def test_call_takes_a_dotted_name_and_returns_the_result():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox(
            "demo", pool=pool, spec=S.CellSpec.build(["math"])
        )
        assert sandbox.call("math.factorial", 5) == 120
        sandbox.close()


@requires_interpreters
def test_call_respects_the_import_allow_list():
    """Resolution goes through the cell's guarded __import__, not the host's."""
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox(
            "demo", pool=pool, spec=S.CellSpec.build(["math"])
        )
        with pytest.raises(Exception, match="not permitted by policy"):
            sandbox.call("os.getpid")
        sandbox.close()


@requires_interpreters
def test_call_rejects_a_bare_name():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        with pytest.raises(ValueError, match="dotted name"):
            sandbox.call("factorial")
        with pytest.raises(TypeError, match="dotted name"):
            sandbox.call(None)  # type: ignore[arg-type]
        sandbox.close()


@requires_interpreters
def test_reset_is_refused_with_the_reason():
    """Not a stub: a cell genuinely cannot be returned to a pristine state."""
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        with pytest.raises(NotImplementedError, match="cannot be reset"):
            sandbox.reset()
        sandbox.close()


@requires_interpreters
def test_snapshot_carries_configuration_not_guest_state():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox(
            "demo", pool=pool, spec=S.CellSpec.build(["math"]), wall_time_ms=1000
        )
        assert sandbox.snapshot() == {
            "name": "demo",
            "backend": "subinterpreter",
            "allowed_imports": ["math"],
            "wall_time_ms": 1000,
        }
        sandbox.close()


@requires_interpreters
def test_quarantine_abandons_the_cell():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        sandbox.quarantine("policy breach")
        assert pool.stats()["abandoned"] == 1
        assert sandbox.is_alive() is False


@requires_interpreters
def test_tracing_is_refused_rather_than_silently_empty():
    with S.CellPool(warm_per_spec=0) as pool:
        sandbox = S.SubinterpreterSandbox("demo", pool=pool, spec=S.CellSpec.build([]))
        with pytest.raises(NotImplementedError, match="process-backend"):
            sandbox.enable_tracing()
        sandbox.close()
