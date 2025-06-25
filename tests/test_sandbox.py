import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate as iso


def test_spawn_returns_sandbox():
    sb = iso.spawn("t1")
    try:
        assert isinstance(sb, iso.Sandbox)
    finally:
        sb.close()


def test_exec_runs_code_and_recv():
    sb = iso.spawn("t2")
    try:
        sb.exec("post(42)")
        assert sb.recv(timeout=0.5) == 42
    finally:
        sb.close()


def test_call_returns_result():
    sb = iso.spawn("t3")
    try:
        result = sb.call("math.sqrt", 9)
        assert result == 3.0
    finally:
        sb.close()


def test_recv_timeout_raises():
    sb = iso.spawn("t4")
    try:
        with pytest.raises(TimeoutError):
            sb.recv(timeout=0.1)
    finally:
        sb.close()
