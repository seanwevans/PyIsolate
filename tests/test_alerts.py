import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def test_alert_on_policy_violation():
    called = {}
    sup = iso.Supervisor()
    sup.register_alert_handler(lambda sb, err: called.setdefault(sb, err))
    sb = sup.spawn("alert")
    try:
        sb.exec("import pyisolate as iso; raise iso.PolicyError('boom')")
        with assert_policy_error():
            sb.recv(timeout=0.5)
    finally:
        sb.close()
        sup.shutdown()
    assert "alert" in called


def test_alert_handler_failure_does_not_stop_others():
    import logging

    from pyisolate.observability.alerts import AlertManager

    manager = AlertManager()
    calls: list[str] = []

    def bad(sb, err):
        calls.append("bad")
        raise RuntimeError("boom")

    def good(sb, err):
        calls.append("good")

    manager.register(bad)
    manager.register(good)

    logs: list[logging.LogRecord] = []

    class ListHandler(logging.Handler):
        def emit(self, record):
            logs.append(record)

    logger = logging.getLogger("pyisolate.observability.alerts")
    handler = ListHandler()
    logger.addHandler(handler)
    try:
        errors = manager.notify("sb", Exception("policy"))
    finally:
        logger.removeHandler(handler)

    assert calls == ["bad", "good"]
    assert len(errors) == 1
    assert len(logs) == 1
    assert "alert callback" in logs[0].getMessage()


from contextlib import contextmanager


@contextmanager
def assert_policy_error():
    caught = type("Caught", (), {"value": None})()
    try:
        yield caught
    except iso.PolicyError as exc:
        caught.value = exc
    else:
        raise AssertionError("PolicyError not raised")


def test_denied_operation_emits_structured_telemetry(tmp_path):
    p = iso.policy.Policy().allow_fs(str(tmp_path))
    sup = iso.Supervisor()
    sb = sup.spawn("deny-telemetry", policy=p)
    try:
        sb.exec("open('/etc/hosts').read()")
        with assert_policy_error() as caught:
            sb.recv(timeout=1)
    finally:
        sup.shutdown()

    event = caught.value.denial_event
    assert event is not None
    assert event.to_dict() == {
        "cell": "deny-telemetry",
        "capability": "filesystem",
        "attempted_action": "open:/etc/hosts",
        "policy_rule": f"allow_fs:{tmp_path.resolve(strict=False)}",
        "kernel_decision": "not_evaluated",
        "broker_decision": "deny",
    }
    assert sb.get_denial_events() == [event.to_dict()]
