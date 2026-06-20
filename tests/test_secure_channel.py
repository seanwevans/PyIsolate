"""Tests for the length-framed :class:`SecureChannel` transport wiring."""

import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pyisolate.broker.channel import (
    LENGTH_PREFIX_BYTES,
    SecureChannel,
    secure_channel_pair,
)
from pyisolate.broker.crypto import MIN_FRAME_LEN, CryptoBroker


def _keypair():
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


class Wire:
    """In-memory byte buffer with optional read-chunk capping and EOF."""

    def __init__(self, chunk=None):
        self.buf = bytearray()
        self.chunk = chunk
        self.closed = False

    def write(self, data):
        self.buf.extend(data)

    def read(self, n):
        if not self.buf:
            return b""
        cap = n if self.chunk is None else min(n, self.chunk)
        take = min(cap, len(self.buf))
        out = bytes(self.buf[:take])
        del self.buf[:take]
        return out


def one_way(*, max_frame_len=4096, chunk=None):
    """Build a sender/receiver channel pair over a single shared wire."""
    client_priv, client_pub = _keypair()
    server_priv, server_pub = _keypair()
    cb = CryptoBroker(
        client_priv, server_pub, max_frame_len=max_frame_len, role="client"
    )
    sb = CryptoBroker(
        server_priv, client_pub, max_frame_len=max_frame_len, role="server"
    )
    wire = Wire(chunk=chunk)
    sender = SecureChannel(cb, send=wire.write, recv=lambda n: b"")
    receiver = SecureChannel(sb, send=lambda d: None, recv=wire.read)
    return sender, receiver, wire


def test_pair_roundtrip_both_directions():
    client, server = secure_channel_pair()
    client.send_message(b"hello server")
    assert server.recv_message() == b"hello server"
    server.send_message(b"hello client")
    assert client.recv_message() == b"hello client"


def test_pair_preserves_message_order():
    client, server = secure_channel_pair()
    messages = [f"msg-{i}".encode() for i in range(20)]
    for msg in messages:
        client.send_message(msg)
    received = [server.recv_message() for _ in messages]
    assert received == messages


def test_empty_payload_roundtrips():
    client, server = secure_channel_pair()
    client.send_message(b"")
    assert server.recv_message() == b""


def test_default_max_message_len_tracks_broker():
    sender, _receiver, _wire = one_way(max_frame_len=1234)
    assert sender.max_message_len == 1234


def test_partial_reads_are_reassembled():
    # A transport that dribbles one byte per read still yields whole frames.
    sender, receiver, _wire = one_way(chunk=1)
    sender.send_message(b"reassemble me")
    assert receiver.recv_message() == b"reassemble me"


def test_oversized_declared_length_rejected_before_read():
    _sender, receiver, wire = one_way(max_frame_len=64)
    # Forge a header that claims a frame larger than the channel allows; no body
    # is supplied, proving the length is rejected before any frame read.
    wire.write((10_000).to_bytes(LENGTH_PREFIX_BYTES, "big"))
    with pytest.raises(ValueError, match="exceeds max_message_len"):
        receiver.recv_message()


def test_zero_declared_length_rejected():
    _sender, receiver, wire = one_way()
    wire.write((0).to_bytes(LENGTH_PREFIX_BYTES, "big"))
    with pytest.raises(ValueError, match="zero"):
        receiver.recv_message()


def test_eof_midframe_raises():
    _sender, receiver, wire = one_way()
    # Announce a 32-byte frame but provide only part of it, then EOF.
    wire.write((32).to_bytes(LENGTH_PREFIX_BYTES, "big"))
    wire.write(b"\x00" * 10)
    with pytest.raises(EOFError):
        receiver.recv_message()


def test_tampered_frame_rejected():
    sender, receiver, wire = one_way()
    sender.send_message(b"authentic")
    # Flip a byte in the ciphertext region (past header + nonce).
    flip = LENGTH_PREFIX_BYTES + 12 + 1
    wire.buf[flip] ^= 0xFF
    with pytest.raises(ValueError, match="decryption failed"):
        receiver.recv_message()


def test_replayed_frame_rejected():
    sender, receiver, wire = one_way()
    sender.send_message(b"once")
    # Capture the framed bytes, deliver once, then replay the identical frame.
    captured = bytes(wire.buf)
    assert receiver.recv_message() == b"once"
    wire.write(captured)
    with pytest.raises(ValueError, match="replay"):
        receiver.recv_message()


def test_send_rejects_payload_over_limit():
    sender, _receiver, _wire = one_way(max_frame_len=64)
    too_big = b"x" * (64 - MIN_FRAME_LEN + 1)
    with pytest.raises(ValueError, match="exceeds max_message_len"):
        sender.send_message(too_big)


def test_send_allows_payload_at_exact_limit():
    sender, receiver, _wire = one_way(max_frame_len=64)
    exact = b"x" * (64 - MIN_FRAME_LEN)
    sender.send_message(exact)
    assert receiver.recv_message() == exact


def test_constructor_rejects_invalid_max_message_len():
    cb_priv, peer_pub = _keypair()
    _peer_priv, _ = _keypair()
    broker = CryptoBroker(cb_priv, peer_pub, role="client")
    with pytest.raises(ValueError, match="max_message_len"):
        SecureChannel(
            broker, send=lambda d: None, recv=lambda n: b"", max_message_len=0
        )


def test_concurrent_senders_preserve_frame_integrity():
    # Multiple threads framing onto one transport must not interleave their
    # counter assignment and wire order, or the receiver would reject frames.
    client, server = secure_channel_pair()
    count = 50
    barrier = threading.Barrier(count)
    errors = []

    def send(i):
        try:
            barrier.wait()
            client.send_message(f"payload-{i:03d}".encode())
        except Exception as exc:  # pragma: no cover - surfaced via errors list
            errors.append(exc)

    threads = [threading.Thread(target=send, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    received = [server.recv_message() for _ in range(count)]
    for thread in threads:
        thread.join()

    assert not errors
    assert sorted(received) == sorted(f"payload-{i:03d}".encode() for i in range(count))
