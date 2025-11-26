"""Async I/O helpers based on ``io_uring``.

The functions fall back to ``asyncio`` when the optional ``uring`` module is
missing.  This keeps the broker non-blocking even on systems without
``io_uring`` bindings installed.
"""

from __future__ import annotations

import asyncio
import os

try:
    import uring  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    uring = None  # type: ignore


class IOUring:
    """Minimal wrapper around ``io_uring`` for async file descriptor I/O."""

    def __init__(self, entries: int = 8):
        self._ring = None
        if uring is not None:
            ring = uring.io_uring()
            # handle API differences across wrapper versions
            setup = getattr(ring, "setup", None) or getattr(ring, "queue_init", None)
            if setup is not None:
                setup(entries)
            self._ring = ring

    async def read(self, fd: int, nbytes: int) -> bytes:
        """Read ``nbytes`` from ``fd`` asynchronously."""
        if self._ring is None:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, os.read, fd, nbytes)

        buf = bytearray(nbytes)
        sqe = self._ring.get_sqe()
        uring.io_uring_prep_read(sqe, fd, buf, nbytes, 0)
        self._ring.submit_and_wait(1)
        cqe = self._ring.wait_cqe()
        res = self._complete(cqe)
        return bytes(buf[:res])

    async def write(self, fd: int, data: bytes) -> int:
        """Write ``data`` to ``fd`` asynchronously."""
        if self._ring is None:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, os.write, fd, data)

        sqe = self._ring.get_sqe()
        uring.io_uring_prep_write(sqe, fd, data, len(data), 0)
        self._ring.submit_and_wait(1)
        cqe = self._ring.wait_cqe()
        return self._complete(cqe)

    def _complete(self, cqe) -> int:
        """Mark *cqe* as seen and raise :class:`OSError` on failures."""

        res = cqe.res
        # Always acknowledge the completion entry before surfacing any errors so
        # the ring can continue to process subsequent I/O.
        self._ring.cqe_seen(cqe)
        if res < 0:
            err = -res
            raise OSError(err, os.strerror(err))
        return res
