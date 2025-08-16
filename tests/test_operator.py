import importlib
import sys
import types
from pathlib import Path


def load_operator():
    pkg = types.ModuleType("pyisolate")
    pkg.__path__ = [str(Path(__file__).resolve().parent.parent / "pyisolate")]
    supervisor_stub = types.ModuleType("pyisolate.supervisor")
    supervisor_stub.Supervisor = object  # placeholder to satisfy import
    orig_pkg = sys.modules.get("pyisolate")
    orig_supervisor = sys.modules.get("pyisolate.supervisor")
    sys.modules["pyisolate"] = pkg
    sys.modules["pyisolate.supervisor"] = supervisor_stub
    sys.modules.pop("pyisolate.operator", None)
    try:
        return importlib.import_module("pyisolate.operator")
    finally:
        if orig_pkg is not None:
            sys.modules["pyisolate"] = orig_pkg
        else:
            sys.modules.pop("pyisolate", None)
        if orig_supervisor is not None:
            sys.modules["pyisolate.supervisor"] = orig_supervisor
        else:
            sys.modules.pop("pyisolate.supervisor", None)


def test_operator_module():
    op = load_operator()
    assert hasattr(op, "run_operator")
    assert callable(op.run_operator)
    assert hasattr(op, "scale_sandboxes")


def test_operator_add_delete(monkeypatch):
    op = load_operator()
    events = [
        {"type": "ADDED", "object": {"metadata": {"name": "sb"}}},
        {"type": "DELETED", "object": {"metadata": {"name": "sb"}}},
    ]

    class FakeWatch:
        def stream(self, *args, **kwargs):
            for ev in events:
                yield ev

    fake_client = types.SimpleNamespace(
        CustomObjectsApi=lambda: types.SimpleNamespace(
            list_namespaced_custom_object=lambda *a, **kw: None
        )
    )
    fake_config = types.SimpleNamespace(load_incluster_config=lambda: None)
    fake_watch_module = types.SimpleNamespace(Watch=lambda: FakeWatch())
    fake_k8s = types.SimpleNamespace(
        client=fake_client, config=fake_config, watch=fake_watch_module
    )

    monkeypatch.setitem(sys.modules, "kubernetes", fake_k8s)
    monkeypatch.setitem(sys.modules, "kubernetes.client", fake_client)
    monkeypatch.setitem(sys.modules, "kubernetes.config", fake_config)
    monkeypatch.setitem(sys.modules, "kubernetes.watch", fake_watch_module)

    spawned = {}

    class FakeSandbox:
        def __init__(self, name: str):
            self.name = name
            self.closed = False

        def close(self):  # pragma: no cover - exercised indirectly
            self.closed = True

    class FakeSupervisor:
        def spawn(self, name: str):
            sb = FakeSandbox(name)
            spawned[name] = sb
            return sb

    monkeypatch.setattr(op, "Supervisor", FakeSupervisor)

    op.run_operator("default")

    assert "sb" in spawned
    assert spawned["sb"].closed
