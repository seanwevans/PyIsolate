import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


def test_tracing_records_exec():
    sb = iso.spawn("trace")
    try:
        sb.enable_tracing()
        sb.exec("post('x')")
        sb.recv(timeout=0.5)
        log = sb.get_syscall_log()
        assert any("post('x')" in entry for entry in log)
    finally:
        sb.close()


def test_profile_returns_stats():
    sb = iso.spawn("prof")
    try:
        sb.exec("post(1)")
        sb.recv(timeout=0.5)
        stats = sb.profile()
        assert stats.cpu_ms >= 0
        assert stats.mem_bytes >= 0
    finally:
        sb.close()
