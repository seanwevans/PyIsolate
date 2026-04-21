import os
import socket
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@pytest.mark.adversarial
def test_adversarial_syntax_error_does_not_poison_sandbox():
    sb = iso.spawn(_name("adversarial"))
    try:
        sb.exec("def broken(:\n    pass")
        with pytest.raises(SyntaxError):
            sb.recv(timeout=1)

        sb.exec("post(41 + 1)")
        assert sb.recv(timeout=1) == 42
    finally:
        sb.close()


@pytest.mark.runaway_cpu
def test_runaway_cpu_loop_is_stopped_by_quota(monkeypatch):
    import pyisolate.runtime.thread as thread_mod

    def fake_thread_time():
        fake_thread_time.current += 0.003
        return fake_thread_time.current

    fake_thread_time.current = 0.0
    monkeypatch.setattr(thread_mod.time, "thread_time", fake_thread_time)

    sb = iso.spawn(_name("cpu"), cpu_ms=2)
    try:
        sb.exec("pass")
        with pytest.raises(iso.CPUExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


@pytest.mark.memory_exhaustion
def test_memory_exhaustion_is_stopped_by_quota():
    sb = iso.spawn(_name("mem"), mem_bytes=64 * 1024)
    try:
        sb.exec("x = 'A' * (2 * 1024 * 1024)")
        with pytest.raises(iso.MemoryExceeded):
            sb.recv(timeout=1)
    finally:
        sb.close()


@pytest.mark.import_escape
def test_import_escape_blocked_by_allowlist():
    sb = iso.spawn(_name("import"), allowed_imports=["math"])
    try:
        sb.exec("import os")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


@pytest.mark.policy_bypass
def test_file_and_network_policy_bypass_attempts_are_blocked(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    allowed_file = allowed_dir / "ok.txt"
    allowed_file.write_text("ok", encoding="utf-8")

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    host, port = srv.getsockname()

    p = policy.Policy().allow_fs(str(allowed_dir)).allow_tcp(f"{host}:{port}")
    sb = iso.spawn(_name("policy"), policy=p)
    try:
        sb.exec(f"post(open({str(allowed_file)!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec("post(open('/etc/hosts').read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec("import socket; s=socket.socket(); s.connect(('8.8.8.8', 53))")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()
        srv.close()


@pytest.mark.race
@pytest.mark.no_gil
def test_spawn_and_exec_race_under_parallel_load():
    def worker(i: int) -> int:
        sb = iso.spawn(_name(f"race{i}"))
        try:
            sb.exec(f"post({i} * {i})")
            return sb.recv(timeout=1)
        finally:
            sb.close()

    with ThreadPoolExecutor(max_workers=12) as pool:
        values = list(pool.map(worker, range(48)))

    assert sorted(values) == sorted(i * i for i in range(48))


@pytest.mark.soak
def test_soak_spawn_kill_cycles():
    cycles = int(os.getenv("PYISOLATE_SOAK_CYCLES", "250"))
    for i in range(cycles):
        sb = iso.spawn(_name("soak"))
        try:
            sb.exec("post('ok')")
            assert sb.recv(timeout=1) == "ok"
        finally:
            sb.close()


@pytest.mark.crash_injection
def test_guest_crash_isolation_and_recovery():
    sb = iso.spawn(_name("crash"))
    try:
        sb.exec("raise RuntimeError('boom')")
        with pytest.raises(RuntimeError):
            sb.recv(timeout=1)

        sb.exec("post('recovered')")
        assert sb.recv(timeout=1) == "recovered"
    finally:
        sb.close()
