import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy


def _assert_policy_error(name: str, source: str, *, imports=()):
    p = policy.Policy()
    for module in imports:
        p.allow_import(module)
    sb = iso.spawn(name, policy=p)
    try:
        sb.exec(source)
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_absent_import_policy_fails_closed():
    sb = iso.spawn("no-imports")
    try:
        sb.exec("import math; post(math.sqrt(4))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_escape_attempt_file_read():
    sb = iso.spawn("escape1", policy=policy.Policy().allow_import("pathlib"))
    try:
        sb.exec("import pathlib; post(pathlib.Path('/etc/hosts').read_text())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_time_side_channel():
    sb = iso.spawn("escape2", policy=policy.Policy().allow_import("time"))
    try:
        sb.exec("import time; post(time.perf_counter())")
        first = sb.recv(timeout=1)
        sb.exec("import time; post(time.perf_counter())")
        second = sb.recv(timeout=1)
        assert abs(second - first) <= 0.001
    finally:
        sb.close()


@pytest.mark.parametrize(
    ("name", "module", "source"),
    [
        ("os-open", "os", "import os; os.open('/etc/hosts', os.O_RDONLY)"),
        ("os-system", "os", "import os; os.system('true')"),
        ("os-exec", "os", "import os; os.execv('/bin/true', ['true'])"),
        ("os-spawn", "os", "import os; os.spawnlp(os.P_WAIT, 'true', 'true')"),
        (
            "subprocess-popen",
            "subprocess",
            "import subprocess; subprocess.Popen(['true'])",
        ),
        (
            "socket-create-connection",
            "socket",
            "import socket; socket.create_connection(('127.0.0.1', 9), timeout=0.01)",
        ),
        (
            "socket-raw",
            "socket",
            "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW)",
        ),
        ("socket-socketpair", "socket", "import socket; socket.socketpair()"),
        ("ctypes-import", "ctypes", "import ctypes"),
        ("multiprocessing-import", "multiprocessing", "import multiprocessing"),
    ],
)
def test_escape_surface_bypasses_are_blocked(name, module, source):
    _assert_policy_error(f"escape-{name}", source, imports=[module])
