import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import os

import pyisolate as iso


def test_checkpoint_roundtrip():
    key = os.urandom(32)
    sb = iso.spawn("cp")
    try:
        sb.exec("post(5)")
        assert sb.recv(timeout=0.5) == 5
        blob = iso.checkpoint(sb, key)
        sb2 = iso.restore(blob, key)
        try:
            sb2.exec("post(6)")
            assert sb2.recv(timeout=0.5) == 6
        finally:
            sb2.close()
    finally:
        pass
