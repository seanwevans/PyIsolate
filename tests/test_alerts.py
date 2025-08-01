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


from contextlib import contextmanager


@contextmanager
def assert_policy_error():
    try:
        yield
    except iso.PolicyError:
        pass
    else:
        raise AssertionError("PolicyError not raised")
