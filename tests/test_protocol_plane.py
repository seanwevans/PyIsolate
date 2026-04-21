from pyisolate.capabilities import ROOT
from pyisolate.runtime.protocol import CallRequest, ExecRequest
from pyisolate.runtime.thread import SandboxThread
from pyisolate.supervisor import Supervisor


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

        assert thread.call("builtins.len", [1, 2, 3]) == 3
        assert isinstance(captured[1], CallRequest)
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
