"""Tests for the ``backend="process"`` real process-boundary isolation mode."""

import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso
from pyisolate.runtime import confine, process_backend

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


def test_process_backend_broker_request_granted():
    from pyisolate.runtime.protocol import BrokerRequest

    caps = {"network": {"destinations": ["example.com:443"]}}
    with iso.spawn("proc-broker", backend="process", capabilities=caps) as sb:
        sb.exec("request('network', 'connect', {'host': 'example.com', 'port': 443})")
        req = sb.recv(timeout=5)
        assert isinstance(req, BrokerRequest)
        assert req.capability == "network"
        assert req.action == "connect"
        assert req.payload == {"host": "example.com", "port": 443}


def test_process_backend_broker_request_denied_without_capability():
    # No capabilities granted: the guest's request is refused at the boundary
    # with a PolicyError rather than performing the privileged action.
    with iso.spawn("proc-broker-deny", backend="process") as sb:
        sb.exec("request('network', 'connect', {})")
        with pytest.raises(iso.PolicyError, match="network"):
            sb.recv(timeout=5)


def test_process_backend_broker_request_denied_for_ungranted_capability():
    caps = {"network": {}}
    with iso.spawn("proc-broker-scope", backend="process", capabilities=caps) as sb:
        # A capability the guest was not granted stays denied even though other
        # capabilities are present.
        sb.exec("request('secret', 'read', {})")
        with pytest.raises(iso.PolicyError, match="secret"):
            sb.recv(timeout=5)


def test_microvm_backend_remains_unimplemented():
    # microVM is routed to a dedicated fail-closed admission path: it refuses
    # with a diagnostic (MicroVMUnavailable, a SandboxError, when the host lacks
    # a VMM/KVM; NotImplementedError when capable but the launcher is pending)
    # rather than ever returning a working guest.
    with pytest.raises((iso.SandboxError, NotImplementedError)):
        iso.spawn("proc-vm", backend="microvm")


# -- quota forwarding ------------------------------------------------------


def test_wall_time_quota_kills_a_runaway_guest():
    # A guest that blocks forever burns no CPU, so RLIMIT_CPU never fires; the
    # supervisor-side wall clock is what bounds it.
    sb = iso.spawn(
        "proc-wall", allowed_imports=["time"], backend="process", wall_time_ms=300
    )
    try:
        started = time.monotonic()
        sb.exec("import time; time.sleep(30); post('finished')")
        with pytest.raises(iso.WallTimeExceeded):
            sb.recv(timeout=10)
        assert time.monotonic() - started < 10
        assert sb.termination_reason == "wall_time_exceeded"
        # The guest must already be stopped when the error surfaces, not still
        # burning CPU while the caller handles the exception.
        assert not sb._thread.is_alive()
    finally:
        sb.close()


def test_wall_time_quota_allows_work_that_finishes_in_budget():
    with iso.spawn(
        "proc-wall-ok", allowed_imports=["math"], backend="process", wall_time_ms=10_000
    ) as sb:
        sb.exec("from math import sqrt; post(sqrt(16))")
        assert sb.recv(timeout=10) == 4.0
        # The timer must be disarmed by the completion frame, not left to fire
        # and kill a guest that already finished.
        time.sleep(0.2)
        assert sb._thread.is_alive()


def test_wall_time_quota_rearms_across_sequential_operations():
    with iso.spawn(
        "proc-wall-seq", allowed_imports=["math"], backend="process", wall_time_ms=5_000
    ) as sb:
        for expected in (2.0, 3.0, 4.0):
            sb.exec(f"from math import sqrt; post(sqrt({expected ** 2}))")
            assert sb.recv(timeout=10) == expected
        assert sb._thread.is_alive()


def test_open_files_quota_reaches_the_guest_as_an_rlimit():
    with iso.spawn(
        "proc-nofile",
        allowed_imports=["resource"],
        backend="process",
        open_files_max=32,
    ) as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert any(item.startswith("nofile=") for item in report["rlimits"])
        sb.exec("import resource; post(resource.getrlimit(resource.RLIMIT_NOFILE)[0])")
        soft = sb.recv(timeout=5)
    # Headroom is added for stdio and the supervisor channel, but the guest is
    # still bounded rather than inheriting the host's limit.
    assert soft == 32 + confine._NOFILE_CHANNEL_HEADROOM


def test_cpu_quota_reaches_the_guest_as_an_rlimit():
    with iso.spawn(
        "proc-cpu", allowed_imports=["resource"], backend="process", cpu_ms=5_000
    ) as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert "cpu=5" in report["rlimits"]
        sb.exec("import resource; post(resource.getrlimit(resource.RLIMIT_CPU)[0])")
        assert sb.recv(timeout=5) == 5


def test_mem_quota_reaches_the_guest_as_an_rlimit():
    with iso.spawn(
        "proc-mem",
        allowed_imports=["resource"],
        backend="process",
        mem_bytes=512 * 1024 * 1024,
    ) as sb:
        report = sb._thread.wait_confined(timeout=5)
        assert f"as={512 * 1024 * 1024}" in report["rlimits"]


def test_sub_second_cpu_budget_rounds_up_and_warns(caplog):
    # RLIMIT_CPU has one-second granularity. Rounding up is honest only if it is
    # visible, so the weaker-than-requested limit is logged.
    with caplog.at_level("WARNING", logger="pyisolate.runtime.process_backend"):
        assert process_backend._cpu_seconds_from_ms(50) == 1
    assert "below RLIMIT_CPU's one-second granularity" in caplog.text
    # A budget that fits the granularity rounds without a warning.
    caplog.clear()
    with caplog.at_level("WARNING", logger="pyisolate.runtime.process_backend"):
        assert process_backend._cpu_seconds_from_ms(2_500) == 3
    assert caplog.text == ""
    assert process_backend._cpu_seconds_from_ms(None) is None


@pytest.mark.parametrize(
    "quota",
    ["network_ops_max", "output_bytes_max", "child_work_max", "numa_node"],
)
def test_unenforceable_quotas_are_refused_not_silently_ignored(quota):
    # These used to be accepted and dropped on the floor, leaving callers with a
    # limit that did nothing in the backend documented as the security boundary.
    with pytest.raises(NotImplementedError, match=quota):
        iso.spawn(f"proc-unsupported-{quota}", backend="process", **{quota: 1})


def test_supported_quotas_are_not_refused():
    with iso.spawn(
        "proc-supported",
        backend="process",
        cpu_ms=5_000,
        mem_bytes=512 * 1024 * 1024,
        wall_time_ms=10_000,
        open_files_max=64,
    ) as sb:
        assert sb.backend == "process"
# -- guest environment scrubbing ------------------------------------------


def test_guest_does_not_inherit_supervisor_environment(monkeypatch):
    # os.environ routinely holds cloud credentials and API tokens. A guest that
    # can read them has exfiltrated them no matter how well the kernel confines
    # the rest of the process.
    monkeypatch.setenv("PYISOLATE_TEST_SECRET", "hunter2-supersecret")
    with iso.spawn("proc-env", allowed_imports=["os"], backend="process") as sb:
        sb.exec("import os; post(os.environ.get('PYISOLATE_TEST_SECRET'))")
        assert sb.recv(timeout=5) is None


def test_guest_environment_is_an_allowlist_not_a_denylist(monkeypatch):
    # A newly-invented variable must not reach the guest: the child env is built
    # from a fixed allow-list, so anything unanticipated is withheld by default.
    monkeypatch.setenv("SOME_FUTURE_CREDENTIAL", "leaked")
    with iso.spawn("proc-env-allow", allowed_imports=["os"], backend="process") as sb:
        sb.exec("import os; post(sorted(os.environ))")
        names = sb.recv(timeout=5)
    assert "SOME_FUTURE_CREDENTIAL" not in names
    assert set(names) <= {"PATH", *process_backend.ENV_PASSTHROUGH}


def test_guest_path_is_fixed_not_the_supervisors(monkeypatch):
    monkeypatch.setenv("PATH", "/home/someuser/.secret-toolchain/bin")
    with iso.spawn("proc-env-path", allowed_imports=["os"], backend="process") as sb:
        sb.exec("import os; post(os.environ.get('PATH'))")
        assert sb.recv(timeout=5) == process_backend.DEFAULT_CHILD_PATH


def test_build_child_env_forwards_only_allowlisted_variables():
    source = {
        "AWS_SECRET_ACCESS_KEY": "nope",
        "GITHUB_TOKEN": "nope",
        "LANG": "en_US.UTF-8",
        "PYTHONPATH": "/opt/src",
    }
    env = process_backend.build_child_env(source=source)
    assert env["LANG"] == "en_US.UTF-8"
    assert env["PYTHONPATH"] == "/opt/src"
    assert env["PATH"] == process_backend.DEFAULT_CHILD_PATH
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env


def test_build_child_env_extra_is_deliberate_and_wins():
    # Anything the caller passes explicitly is intentional configuration, so it
    # overrides the allow-listed value rather than being dropped.
    source = {"LANG": "C"}
    env = process_backend.build_child_env(
        {"LANG": "en_GB.UTF-8", "APP_MODE": "test"}, source=source
    )
    assert env["LANG"] == "en_GB.UTF-8"
    assert env["APP_MODE"] == "test"


def test_explicit_env_reaches_the_guest():
    proc = process_backend.ProcessSandbox(
        "proc-env-extra",
        allowed_imports=["os"],
        env={"APP_MODE": "production"},
    )
    try:
        proc.wait_confined(timeout=5)
        proc.exec("import os; post(os.environ.get('APP_MODE'))")
        assert proc.recv(timeout=5) == "production"
    finally:
        proc.stop()
