import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso


@pytest.mark.xfail(reason="Sandbox lacks real syscall filtering")
def test_escape_attempt_file_read():
    sb = iso.spawn("escape1")
    try:
        sb.exec("import pathlib; post(pathlib.Path('/etc/hosts').read_text())")
        sb.recv(timeout=1)
    finally:
        sb.close()


@pytest.mark.xfail(reason="Side channel protections not implemented")
def test_time_side_channel():
    sb = iso.spawn("escape2")
    try:
        sb.exec("import time; post(time.perf_counter())")
        first = sb.recv(timeout=1)
        sb.exec("import time; post(time.perf_counter())")
        second = sb.recv(timeout=1)
        assert abs(second - first) <= 0.001
    finally:
        sb.close()
