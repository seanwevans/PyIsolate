"""Tests for the fabric: cells in worker processes that can actually be killed.

Note what these tests do *not* need. The in-process cell backend's runaway
tests have to shell out to a fresh interpreter, because a stranded cell pins a
thread forever and would hang pytest at exit. Here the runaway tests run
inline: the fabric kills the worker, so the strand dies with it. That
difference is the whole point of this layer, and it shows up in the shape of
the test file.
"""

import os
import sys
import time

import pytest

from pyisolate import errors
from pyisolate.runtime import fabric as F
from pyisolate.runtime import subinterpreter as S

requires_interpreters = pytest.mark.skipif(
    not S.is_available(),
    reason=f"needs CPython {S.MIN_PYTHON[0]}.{S.MIN_PYTHON[1]}+ for cells",
)


@pytest.fixture
def pool():
    """A small fabric, always torn down so no worker outlives the test."""
    p = F.WorkerPool(max_workers=4, cells_per_worker=4, warm_per_spec=0)
    try:
        yield p
    finally:
        p.close()


def _wait_gone(pid, timeout=5.0):
    """True once *pid* is no longer running.

    ``os.kill(pid, 0)`` still succeeds for a zombie -- a process that has
    exited but has not been waited on yet -- so a signal probe alone would
    report a killed worker as alive. Read the state out of procfs and treat
    ``Z`` as gone, so the test measures "stopped running" rather than "already
    collected", which is the fabric's actual guarantee.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                # "pid (comm) state ..." -- comm can contain spaces and parens,
                # so split after the last ')'.
                state = fh.read().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            return True
        if state == "Z":
            return True
        time.sleep(0.01)
    return False


# --- availability ---------------------------------------------------------


def test_is_available_tracks_the_running_build():
    expected = sys.version_info[:2] >= S.MIN_PYTHON
    assert S.is_available() is expected


@pytest.mark.skipif(S.is_available(), reason="this build has sub-interpreters")
def test_fabric_fails_closed_naming_the_process_backend():
    """A fabric cannot invent cells; it says what to use instead."""
    with pytest.raises(errors.SandboxError) as excinfo:
        S.require_available_for_fabric()
    message = str(excinfo.value)
    assert "backend='fabric'" in message
    assert "3.14" in message
    assert "backend='process'" in message


# --- pool configuration (no worker needed) --------------------------------


def test_pool_rejects_nonsense_sizes():
    with pytest.raises(ValueError, match="max_workers"):
        F.WorkerPool(max_workers=0)
    with pytest.raises(ValueError, match="cells_per_worker"):
        F.WorkerPool(cells_per_worker=0)


def test_rebuild_never_resolves_an_arbitrary_name():
    """Only the exception's *name* crosses the boundary, so it is mapped.

    Looking the name up dynamically would let a worker -- which runs guest code
    -- name any class in the supervisor and have it constructed here.
    """
    assert isinstance(F._rebuild("ValueError", "x"), ValueError)
    assert isinstance(F._rebuild("PolicyError", "x"), errors.PolicyError)
    exc = F._rebuild("os.system", "rm -rf /")
    assert isinstance(exc, errors.SandboxError)
    assert "os.system" in str(exc)


# --- the cell ABI through a worker ----------------------------------------


@requires_interpreters
def test_exec_and_recv_round_trip(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, allowed_imports=["math"])
    try:
        sandbox.exec("from math import sqrt; post(sqrt(2))")
        assert sandbox.recv(timeout=10) == pytest.approx(1.4142135623730951)
    finally:
        sandbox.close()


@requires_interpreters
def test_call_resolves_a_dotted_name_in_the_cell(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, allowed_imports=["math"])
    try:
        assert sandbox.call("math.factorial", 5) == 120
    finally:
        sandbox.close()


@requires_interpreters
def test_call_rejects_a_bare_name(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        with pytest.raises(ValueError, match="dotted name"):
            sandbox.call("factorial")
        with pytest.raises(TypeError, match="dotted name"):
            sandbox.call(None)  # type: ignore[arg-type]
    finally:
        sandbox.close()


@requires_interpreters
def test_the_import_allow_list_is_enforced_inside_the_worker(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, allowed_imports=["math"])
    try:
        with pytest.raises(Exception, match="not permitted by policy"):
            sandbox.exec("import os")
    finally:
        sandbox.close()


@requires_interpreters
def test_log_metric_and_request_reach_the_supervisor(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        sandbox.exec(
            "log('info', 'hello', k=1)\n"
            "metric('m', 3)\n"
            "request('read_path', '/etc/hosts')\n"
        )
        assert sandbox.get_broker_requests() == [
            {"capability": "read_path", "args": ["/etc/hosts"], "kwargs": {}}
        ]
    finally:
        sandbox.close()


@requires_interpreters
def test_a_guest_error_surfaces_as_the_matching_exception(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        with pytest.raises(Exception) as excinfo:
            sandbox.exec("raise ValueError('boom')")
        assert "boom" in str(excinfo.value)
    finally:
        sandbox.close()


@requires_interpreters
def test_worker_reports_the_build_it_is_running(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        info = sandbox._worker.info
        assert isinstance(info["pid"], int)
        assert info["python"].startswith("3.")
        assert isinstance(info["free_threaded"], bool)
    finally:
        sandbox.close()


# --- placement ------------------------------------------------------------


@requires_interpreters
def test_tenants_do_not_share_a_worker_by_default(pool):
    """Fate-sharing is the cost of packing tenants together, so it is opt-in."""
    a = F.FabricSandbox("a", pool=pool, tenant="acme")
    b = F.FabricSandbox("b", pool=pool, tenant="globex")
    try:
        assert a._worker.id != b._worker.id
        assert a._worker.tenant == "acme"
        assert b._worker.tenant == "globex"
    finally:
        a.close()
        b.close()


@requires_interpreters
def test_one_tenants_cells_share_a_worker_until_it_is_full():
    p = F.WorkerPool(max_workers=4, cells_per_worker=2, warm_per_spec=0)
    try:
        cells = [F.FabricSandbox(f"c{i}", pool=p, tenant="acme") for i in range(3)]
        try:
            workers = {c._worker.id for c in cells}
            # Two fit in the first worker; the third opens a second one.
            assert len(workers) == 2
        finally:
            for c in cells:
                c.close()
    finally:
        p.close()


@requires_interpreters
def test_tenant_isolation_off_packs_them_together():
    p = F.WorkerPool(
        max_workers=4, cells_per_worker=4, tenant_isolation=False, warm_per_spec=0
    )
    try:
        a = F.FabricSandbox("a", pool=p, tenant="acme")
        b = F.FabricSandbox("b", pool=p, tenant="globex")
        try:
            assert a._worker.id == b._worker.id
            assert p.stats()["tenant_isolation"] is False
        finally:
            a.close()
            b.close()
    finally:
        p.close()


@requires_interpreters
def test_capacity_is_refused_with_an_actionable_message():
    p = F.WorkerPool(max_workers=1, cells_per_worker=1, warm_per_spec=0)
    try:
        first = F.FabricSandbox("a", pool=p, tenant="acme")
        try:
            with pytest.raises(errors.SandboxError, match="at capacity"):
                F.FabricSandbox("b", pool=p, tenant="globex")
        finally:
            first.close()
    finally:
        p.close()


# --- the kill domain ------------------------------------------------------


@requires_interpreters
def test_a_runaway_cell_is_reclaimed_by_killing_its_worker(pool):
    """The thing that is impossible in-process.

    In ``backend="subinterpreter"`` this cell would be abandoned and its thread
    pinned for the life of the process. Here the deadline kills the worker, and
    the strand dies with it.
    """
    sandbox = F.FabricSandbox("runaway", pool=pool, tenant="acme", wall_time_ms=400)
    pid = sandbox._worker.pid

    with pytest.raises(errors.WallTimeExceeded) as excinfo:
        sandbox.exec("while True:\n    pass")

    message = str(excinfo.value)
    assert "cannot be reclaimed" in message
    assert "killed" in message
    assert _wait_gone(pid), "the worker process outlived the recycle"
    assert sandbox.is_alive() is False
    assert pool.stats()["workers_killed"] == 1


@requires_interpreters
def test_a_runaway_does_not_touch_another_tenant(pool):
    victim = F.FabricSandbox("runaway", pool=pool, tenant="acme", wall_time_ms=400)
    bystander = F.FabricSandbox(
        "fine", pool=pool, tenant="globex", allowed_imports=["math"]
    )
    try:
        assert victim._worker.id != bystander._worker.id
        with pytest.raises(errors.WallTimeExceeded):
            victim.exec("while True:\n    pass")

        # The bystander's worker was never touched.
        assert bystander.is_alive()
        bystander.exec("from math import sqrt; post(sqrt(9))")
        assert bystander.recv(timeout=10) == 3.0
    finally:
        bystander.close()


@requires_interpreters
def test_the_tenant_can_keep_working_after_its_worker_is_recycled(pool):
    victim = F.FabricSandbox("runaway", pool=pool, tenant="acme", wall_time_ms=400)
    with pytest.raises(errors.WallTimeExceeded):
        victim.exec("while True:\n    pass")

    replacement = F.FabricSandbox("after", pool=pool, tenant="acme")
    try:
        replacement.exec("post(1 + 1)")
        assert replacement.recv(timeout=10) == 2
    finally:
        replacement.close()


@requires_interpreters
def test_killing_a_sandbox_kills_its_worker(pool):
    """Unlike a cell's kill(), this one can actually deliver."""
    sandbox = F.FabricSandbox("demo", pool=pool, tenant="acme")
    pid = sandbox._worker.pid
    assert sandbox.kill() is True
    assert _wait_gone(pid)
    assert sandbox.is_alive() is False


@requires_interpreters
def test_quarantine_kills_the_worker_and_records_the_reason(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, tenant="acme")
    pid = sandbox._worker.pid
    sandbox.quarantine("policy breach")
    assert sandbox._quarantine_reason == "policy breach"
    assert _wait_gone(pid)


@requires_interpreters
def test_a_worker_dying_under_us_surfaces_rather_than_hanging(pool):
    """An OOM kill or a segfault must not leave a caller blocked forever."""
    sandbox = F.FabricSandbox("demo", pool=pool, tenant="acme")
    pid = sandbox._worker.pid
    os.kill(pid, 9)
    assert _wait_gone(pid)

    with pytest.raises(errors.SandboxError):
        sandbox.exec("post(1)")
    assert sandbox.is_alive() is False


@requires_interpreters
def test_a_dead_worker_is_reaped_out_of_the_placement_set(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, tenant="acme")
    pid = sandbox._worker.pid
    os.kill(pid, 9)
    assert _wait_gone(pid)
    # The worker is marked unusable when its channel hits EOF, which the reader
    # thread notices a moment after the process dies.
    deadline = time.monotonic() + 5.0
    while sandbox._worker.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)

    stats = pool.stats()
    assert stats["workers_live"] == 0
    assert stats["workers_died"] == 1

    # A new sandbox for the same tenant gets a fresh worker.
    replacement = F.FabricSandbox("after", pool=pool, tenant="acme")
    try:
        assert replacement._worker.pid != pid
        replacement.exec("post('alive')")
        assert replacement.recv(timeout=10) == "alive"
    finally:
        replacement.close()


# --- observability --------------------------------------------------------


@requires_interpreters
def test_worker_report_shows_placement(pool):
    a = F.FabricSandbox("a", pool=pool, tenant="acme")
    b = F.FabricSandbox("b", pool=pool, tenant="globex")
    try:
        report = {row["tenant"]: row for row in pool.worker_report()}
        assert set(report) == {"acme", "globex"}
        for row in report.values():
            assert row["cells"] == 1
            assert row["alive"] is True
            assert row["uptime_s"] >= 0
    finally:
        a.close()
        b.close()


@requires_interpreters
def test_sandbox_stats_name_the_worker_hosting_the_cell(pool):
    sandbox = F.FabricSandbox("demo", pool=pool, tenant="acme")
    try:
        stats = sandbox.stats()
        assert stats["backend"] == "fabric"
        assert stats["tenant"] == "acme"
        assert stats["worker"] == sandbox._worker.id
        assert stats["worker_pid"] == sandbox._worker.pid
        assert stats["fabric"]["workers_live"] >= 1
    finally:
        sandbox.close()


# --- the surface the Sandbox handle delegates to --------------------------


@requires_interpreters
def test_snapshot_carries_configuration_not_guest_state(pool):
    sandbox = F.FabricSandbox(
        "demo",
        pool=pool,
        allowed_imports=["math"],
        tenant="acme",
        wall_time_ms=1000,
    )
    try:
        assert sandbox.snapshot() == {
            "name": "demo",
            "backend": "fabric",
            "tenant": "acme",
            "allowed_imports": ["math"],
            "wall_time_ms": 1000,
        }
    finally:
        sandbox.close()


@requires_interpreters
def test_reset_is_refused_with_the_reason(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        with pytest.raises(NotImplementedError, match="cannot be reset"):
            sandbox.reset()
    finally:
        sandbox.close()


@requires_interpreters
def test_tracing_is_refused_rather_than_silently_empty(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    try:
        with pytest.raises(NotImplementedError, match="no per-cell syscall"):
            sandbox.enable_tracing()
    finally:
        sandbox.close()


@requires_interpreters
def test_using_a_closed_sandbox_is_refused(pool):
    sandbox = F.FabricSandbox("demo", pool=pool)
    sandbox.close()
    with pytest.raises(errors.SandboxError, match="closed"):
        sandbox.exec("post(1)")


# --- pre-warming ----------------------------------------------------------


@requires_interpreters
def test_prewarm_starts_workers_before_the_first_request():
    """A worker costs ~160ms to spawn; a tenant should not pay that inline."""
    p = F.WorkerPool(max_workers=3, cells_per_worker=4, warm_per_spec=0)
    try:
        assert p.prewarm("acme", 2) == 2
        assert p.stats()["workers_live"] == 2

        started_before = p.stats()["workers_started"]
        sandbox = F.FabricSandbox("demo", pool=p, tenant="acme")
        try:
            # The cell landed on an existing worker rather than spawning one.
            assert p.stats()["workers_started"] == started_before
            sandbox.exec("post('warm')")
            assert sandbox.recv(timeout=10) == "warm"
        finally:
            sandbox.close()
    finally:
        p.close()


@requires_interpreters
def test_prewarm_respects_max_workers():
    p = F.WorkerPool(max_workers=1, cells_per_worker=4, warm_per_spec=0)
    try:
        assert p.prewarm("acme", 5) == 1
        assert p.stats()["workers_live"] == 1
    finally:
        p.close()


@requires_interpreters
def test_prewarmed_workers_respect_tenant_isolation():
    """A warm worker for one tenant is not a warm worker for another."""
    p = F.WorkerPool(max_workers=3, cells_per_worker=4, warm_per_spec=0)
    try:
        p.prewarm("acme", 1)
        sandbox = F.FabricSandbox("demo", pool=p, tenant="globex")
        try:
            assert sandbox._worker.tenant == "globex"
            assert p.stats()["workers_live"] == 2
        finally:
            sandbox.close()
    finally:
        p.close()
