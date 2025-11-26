import asyncio
import errno
import os

import pytest

import pyisolate.broker.uring as uring_mod
from pyisolate.broker.uring import IOUring


def test_async_pipe_roundtrip():
    rfd, wfd = os.pipe()
    ring = IOUring()

    async def _io():
        await ring.write(wfd, b"hello")
        os.close(wfd)
        data = await ring.read(rfd, 5)
        os.close(rfd)
        return data

    result = asyncio.run(_io())
    assert result == b"hello"


def _stub_uring_module(result: int):
    class DummyCQE:
        def __init__(self, res: int):
            self.res = res

    class DummyRing:
        def __init__(self):
            self.seen = False

        def setup(self, entries: int):
            self.entries = entries

        def get_sqe(self):
            return object()

        def submit_and_wait(self, n: int):
            return None

        def wait_cqe(self):
            return DummyCQE(result)

        def cqe_seen(self, cqe):
            self.seen = True

    ring = DummyRing()

    class StubUring:
        def __init__(self):
            self.io_uring = lambda: ring

        @staticmethod
        def io_uring_prep_read(*args, **kwargs):
            return None

        @staticmethod
        def io_uring_prep_write(*args, **kwargs):
            return None

    return StubUring(), ring


def test_io_uring_read_error_propagates(monkeypatch):
    stub, ring = _stub_uring_module(-errno.EBADF)
    monkeypatch.setattr(uring_mod, "uring", stub)

    io = IOUring()
    with pytest.raises(OSError) as excinfo:
        asyncio.run(io.read(123, 1))

    assert excinfo.value.errno == errno.EBADF
    assert ring.seen


def test_io_uring_write_error_propagates(monkeypatch):
    stub, ring = _stub_uring_module(-errno.EPIPE)
    monkeypatch.setattr(uring_mod, "uring", stub)

    io = IOUring()
    with pytest.raises(OSError) as excinfo:
        asyncio.run(io.write(123, b""))

    assert excinfo.value.errno == errno.EPIPE
    assert ring.seen
