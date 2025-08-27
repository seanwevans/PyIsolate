import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Use a writable temporary directory for cgroup operations during tests.
os.environ["PYISOLATE_CGROUP_ROOT"] = tempfile.mkdtemp()

import pytest

import pyisolate as iso
from pyisolate import cgroup as _cgroup
from pyisolate.runtime.thread import SandboxThread

# Ensure the cgroup helper writes to the temporary directory even if already imported.
_cgroup._BASE = Path(os.environ["PYISOLATE_CGROUP_ROOT"]) / "pyisolate"


def test_idle_thread_cpu_and_shutdown():
    sup = iso.Supervisor(warm_pool=1)
    sb = sup.spawn("idle-cpu")
    thread = sb._thread
    try:
        # Ensure the sandbox thread attached itself to its cgroup.
        cg_path = thread._cgroup_path
        assert cg_path is not None
        tid = thread.native_id
        for _ in range(50):
            try:
                data = (cg_path / "cgroup.threads").read_text()
                if str(tid) in data:
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.01)
        assert str(tid) in (cg_path / "cgroup.threads").read_text()

        start = time.process_time()
        time.sleep(0.2)
        cpu_used = time.process_time() - start
    finally:
        sb.close()
        sup.shutdown()
    assert cpu_used < 0.05
    assert not thread.is_alive()


def test_thread_metrics_reset_on_reuse():
    t = SandboxThread(name="reset-thread")
    t.start()
    try:
        t.enable_tracing()
        t.exec("post('a')")
        assert t.recv(timeout=0.5) == "a"
        t.exec("raise ValueError('boom')")
        with pytest.raises(ValueError):
            t.recv(timeout=0.5)

        # metrics populated
        s = t.stats
        assert s.operations == 2
        assert s.errors == 1
        assert t.get_syscall_log()

        t.reset("reset-thread-2")

        s = t.stats
        assert s.operations == 0
        assert s.errors == 0
        assert s.latency_sum == 0
        assert all(v == 0 for v in s.latency.values())
        assert t.get_syscall_log() == []

        # tracing disabled after reset
        t.exec("post('b')")
        assert t.recv(timeout=0.5) == "b"
        assert t.get_syscall_log() == []
        assert t.stats.operations == 1
    finally:
        t.stop()
