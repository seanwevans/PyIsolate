"""Length-framed, authenticated message channel over a byte transport.

:class:`CryptoBroker` (see :mod:`pyisolate.broker.crypto`) only knows how to
turn one plaintext message into one AEAD frame and back again; it has no notion
of where a frame begins or ends on the wire.  :class:`SecureChannel` supplies
that missing glue: it prefixes every encrypted frame with a fixed-width length
header so a stream transport (a socket, a pipe, an ``io_uring`` file
descriptor) can be split back into discrete messages, and it bounds the
declared length so a hostile or buggy peer cannot make the receiver allocate or
loop for an oversized frame.

This is the transport-facing layer the cross-process and microVM backends need
in order to carry sandbox traffic over a real byte channel.  The default
in-thread ``subinterpreter`` backend hands message objects between threads
through :class:`queue.Queue` and never serialises to bytes, so it does not use
:class:`SecureChannel`; the channel exists for the backends that *do* cross a
process or machine boundary.
"""

from __future__ import annotations

import threading
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .crypto import DEFAULT_MAX_FRAME_LEN, MIN_FRAME_LEN, CryptoBroker

#: Width of the big-endian length prefix that delimits frames on the wire.
LENGTH_PREFIX_BYTES = 4

#: Largest value representable in the length prefix.
_MAX_PREFIX_VALUE = (1 << (8 * LENGTH_PREFIX_BYTES)) - 1

SendBytes = Callable[[bytes], None]
RecvBytes = Callable[[int], bytes]


class SecureChannel:
    """Encrypted, length-delimited message channel over a byte transport.

    Parameters
    ----------
    broker:
        The :class:`CryptoBroker` that encrypts outgoing messages and decrypts
        incoming ones.  Both ends of a channel must hold brokers derived from
        the same key exchange with matching ``client``/``server`` roles.
    send:
        Callable that writes *all* of the supplied bytes to the transport.
    recv:
        Callable that returns up to ``n`` bytes from the transport, mirroring
        :meth:`socket.socket.recv`.  An empty return value signals that the peer
        closed the transport.
    max_message_len:
        Largest frame the receiver will accept, in bytes.  Defaults to the
        broker's own ``max_frame_len`` so the channel never advertises a bound
        looser than the AEAD layer enforces.
    """

    def __init__(
        self,
        broker: CryptoBroker,
        *,
        send: SendBytes,
        recv: RecvBytes,
        max_message_len: int | None = None,
    ) -> None:
        self._broker = broker
        self._send = send
        self._recv = recv
        limit = broker.max_frame_len if max_message_len is None else max_message_len
        if limit < 1 or limit > _MAX_PREFIX_VALUE:
            raise ValueError(
                "max_message_len must be between 1 and " f"{_MAX_PREFIX_VALUE} bytes"
            )
        self._max_message_len = limit
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()

    @property
    def max_message_len(self) -> int:
        """Largest frame this channel will send or accept, in bytes."""
        return self._max_message_len

    def send_message(self, payload: bytes) -> None:
        """Encrypt ``payload`` and write a length-prefixed frame."""
        # A ChaCha20-Poly1305 frame is exactly the plaintext length plus the
        # nonce and tag, so reject oversized payloads *before* framing -- framing
        # would otherwise consume a nonce counter we then have to throw away,
        # desynchronising the two ends.
        if len(payload) + MIN_FRAME_LEN > self._max_message_len:
            raise ValueError("message exceeds max_message_len")
        # Hold the send lock across both framing and the write: ``frame`` assigns
        # the next nonce counter, and the receiver validates counters in order,
        # so the wire order must match the order counters were handed out.
        # Framing outside the lock would let two senders swap their on-wire order
        # relative to their counters and trip the replay check.
        with self._send_lock:
            frame = self._broker.frame(payload)
            header = len(frame).to_bytes(LENGTH_PREFIX_BYTES, "big")
            self._send(header + frame)

    def recv_message(self) -> bytes:
        """Read one length-prefixed frame, decrypt it, and return plaintext."""
        with self._recv_lock:
            header = self._recv_exact(LENGTH_PREFIX_BYTES)
            length = int.from_bytes(header, "big")
            # Reject before allocating/reading so a bogus length cannot pin
            # memory or spin the recv loop.
            if length > self._max_message_len:
                raise ValueError("declared frame length exceeds max_message_len")
            if length < 1:
                raise ValueError("declared frame length is zero")
            frame = self._recv_exact(length)
            # Decrypt while still holding the lock. ``unframe`` validates the
            # receive nonce counter in strictly increasing order, so it must run
            # in the same order frames were read off the wire. Releasing the lock
            # before decrypting would let a second reader that pulled the *next*
            # frame call ``unframe`` first, present an out-of-order counter, and
            # trip a spurious replay/decrypt failure that drops a valid message.
            # This mirrors the send path, which holds the lock across framing.
            return self._broker.unframe(frame)

    def _recv_exact(self, count: int) -> bytes:
        """Read exactly ``count`` bytes or raise :class:`EOFError`."""
        chunks: list[bytes] = []
        remaining = count
        while remaining > 0:
            chunk = self._recv(remaining)
            if not chunk:
                raise EOFError("transport closed before a full frame arrived")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


class _BytePipe:
    """Unidirectional, thread-safe in-memory byte stream.

    Used to connect both ends of a :func:`secure_channel_pair` in-process for
    tests, the conformance probe, and local demonstrations.  ``read`` follows
    socket semantics: it blocks until at least one byte is available and then
    returns up to ``n`` bytes, returning ``b""`` once the writer has closed.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._cond = threading.Condition()
        self._closed = False

    def write(self, data: bytes) -> None:
        with self._cond:
            if self._closed:
                raise BrokenPipeError("pipe is closed")
            self._buf.extend(data)
            self._cond.notify_all()

    def read(self, n: int) -> bytes:
        with self._cond:
            while not self._buf and not self._closed:
                self._cond.wait()
            if not self._buf:
                return b""
            take = min(n, len(self._buf))
            chunk = bytes(self._buf[:take])
            del self._buf[:take]
            return chunk

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


def _keypair() -> tuple[bytes, bytes]:
    priv = x25519.X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def secure_channel_pair(
    *,
    max_frame_len: int = DEFAULT_MAX_FRAME_LEN,
) -> tuple[SecureChannel, SecureChannel]:
    """Return a connected ``(client, server)`` pair of secure channels.

    Performs a fresh X25519 key exchange, builds matching client/server
    :class:`CryptoBroker` instances, and wires them together with an in-memory
    duplex byte pipe.  Anything sent on one channel can be received, decrypted,
    and authenticated on the other.  Intended for tests, the conformance probe,
    and local demonstrations of the encrypted transport rather than production
    IPC, which supplies its own cross-process transport callables.
    """
    client_priv, client_pub = _keypair()
    server_priv, server_pub = _keypair()

    client_broker = CryptoBroker(
        client_priv, server_pub, max_frame_len=max_frame_len, role="client"
    )
    server_broker = CryptoBroker(
        server_priv, client_pub, max_frame_len=max_frame_len, role="server"
    )

    client_to_server = _BytePipe()
    server_to_client = _BytePipe()

    client = SecureChannel(
        client_broker,
        send=client_to_server.write,
        recv=server_to_client.read,
    )
    server = SecureChannel(
        server_broker,
        send=server_to_client.write,
        recv=client_to_server.read,
    )
    return client, server
