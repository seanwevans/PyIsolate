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
    from pyisolate.observability.alerts import AlertManager
    import logging

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
    try:
        yield
    except iso.PolicyError:
        pass
    else:
        raise AssertionError("PolicyError not raised")
