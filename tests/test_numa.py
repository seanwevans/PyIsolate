import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.bpf.manager import BPFManager

BPFManager._SKEL_CACHE = {}

import pyisolate as iso
from pyisolate import numa


def test_spawn_calls_bind(monkeypatch):
    called = {}

    def fake_bind(node):
        called["node"] = node

    monkeypatch.setattr("pyisolate.runtime.thread.bind_current_thread", fake_bind)
    sb = iso.spawn("n0", numa_node=0)
    try:
        sb.exec("post(1)")
        assert sb.recv(timeout=0.5) == 1
    finally:
        sb.close()
    assert called["node"] == 0


def test_spawn_calls_bind_for_warm_thread(monkeypatch):
    calls = []

    def fake_bind(node):
        calls.append(node)

    monkeypatch.setattr("pyisolate.runtime.thread.bind_current_thread", fake_bind)
    sup = iso.Supervisor(warm_pool=1)
    try:
        sb = sup.spawn("warm-n0", numa_node=1)
        try:
            sb.exec("post(2)")
            assert sb.recv(timeout=0.5) == 2
        finally:
            sb.close()
    finally:
        sup.shutdown()

    assert calls == [1]


def test_parse_cpu_list():
    assert numa._parse_cpu_list("0-2,4,6-7") == {0, 1, 2, 4, 6, 7}
