import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def test_spawn_speed():
    start = time.perf_counter()
    for i in range(5):
        sb = iso.spawn(f"perf{i}")
        sb.close()
    duration = time.perf_counter() - start
    assert duration < 5.0
