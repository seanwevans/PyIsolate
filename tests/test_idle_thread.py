import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def test_idle_thread_cpu_and_shutdown():
    sb = iso.spawn("idle-cpu")
    thread = sb._thread
    try:
        start = time.process_time()
        time.sleep(0.2)
        cpu_used = time.process_time() - start
    finally:
        sb.close()
    assert cpu_used < 0.05
    assert not thread.is_alive()
