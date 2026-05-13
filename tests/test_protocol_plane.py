import pytest

from pyisolate import errors
from pyisolate.capabilities import ROOT, FilesystemCapability
from pyisolate.runtime.protocol import (
    BrokerRequest,
    CallRequest,
    CellOp,
    ExecRequest,
    LogEvent,
    MetricEvent,
    MINIMAL_CELL_ABI,
)
from pyisolate.runtime.thread import SandboxThread
from pyisolate.supervisor import Supervisor


def test_minimal_cell_abi_is_frozen_to_seven_operations():
    assert MINIMAL_CELL_ABI.version == 1
    assert MINIMAL_CELL_ABI.operations == (
        "exec",
        "call",
        "post",
        "recv",
        "log",
        "metric",
        "request",
    )
    assert {op.value for op in CellOp} == set(MINIMAL_CELL_ABI.operations)
    assert not MINIMAL_CELL_ABI.allows("import")


def test_sandbox_thread_uses_structured_requests(monkeypatch):
    thread = SandboxThread(name="proto")
    captured = []
    original_put = thread._inbox.put

    def capture(msg):
        captured.append(msg)
        return original_put(msg)

    monkeypatch.setattr(thread._inbox, "put", capture)

    thread.start()
    try:
        thread.exec("x=1")
        assert isinstance(captured[0], ExecRequest)
        assert captured[0].op is CellOp.EXEC

        assert thread.call("builtins.len", [1, 2, 3]) == 3
        assert isinstance(captured[1], CallRequest)
        assert captured[1].op is CellOp.CALL
    finally:
        thread.stop()


def test_guest_log_metric_and_request_are_channel_events(tmp_path):
    cap_root = tmp_path / "allowed"
    cap_root.mkdir()
    thread = SandboxThread(
        name="abi-events",
        capabilities={"filesystem": FilesystemCapability.from_paths(cap_root)},
    )
    thread.start()
    try:
        thread.exec(
            "log('info', 'ready', component='guest')\n"
            "metric('jobs_total', 1, {'unit': 'count'})\n"
            "request('filesystem', 'stat', {'path': 'allowed'})"
        )

        log_event = thread.recv(timeout=0.5)
        metric_event = thread.recv(timeout=0.5)
        broker_request = thread.recv(timeout=0.5)

        assert log_event == LogEvent(
            level="info", message="ready", fields={"component": "guest"}
        )
        assert metric_event == MetricEvent(
            name="jobs_total", value=1, tags={"unit": "count"}
        )
        assert broker_request == BrokerRequest(
            capability="filesystem", action="stat", payload={"path": "allowed"}
        )
    finally:
        thread.stop()


def test_guest_request_requires_explicit_capability():
    thread = SandboxThread(name="abi-request-denied")
    thread.start()
    try:
        thread.exec("request('filesystem', 'stat', {'path': 'x'})")
        with pytest.raises(
            errors.PolicyError, match="capability request blocked: filesystem"
        ):
            thread.recv(timeout=0.5)
    finally:
        thread.stop()


def test_reload_policy_requires_authenticated_control(tmp_path, monkeypatch):
    sup = Supervisor()
    try:
        called = {}

        def fake_hot_reload(path):
            called["path"] = path

        monkeypatch.setattr(sup._bpf, "hot_reload", fake_hot_reload)
        policy = tmp_path / "policy.json"
        policy.write_text("{}")

        sup.reload_policy(str(policy), ROOT)
        assert called["path"] == str(policy)
    finally:
        sup.shutdown(ROOT)
