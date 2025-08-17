import os
import sys
import time
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Use a writable temporary directory for cgroup operations during tests.
os.environ["PYISOLATE_CGROUP_ROOT"] = tempfile.mkdtemp()

import pyisolate as iso
from pyisolate import cgroup as _cgroup

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
