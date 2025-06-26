import asyncio
import os
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
