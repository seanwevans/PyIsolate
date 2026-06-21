"""Tests for the length-framed :class:`SecureChannel` transport wiring."""

import threading
import time

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


def test_concurrent_recv_decrypts_in_counter_order():
    # ``unframe`` validates the receive nonce counter in strictly increasing
    # order, so decryption must happen in the same order frames are read off the
    # wire. This forces the hazardous interleave deterministically: reader "a"
    # takes the recv lock, reads frame 0, and parks inside ``unframe``; reader
    # "b" is then started and tries to read frame 1. If decryption ran outside
    # the recv lock, reader "b" would unframe frame 1 while the broker still
    # expects frame 0 and raise a spurious replay/decrypt error, silently
    # dropping a valid message.
    client, server = secure_channel_pair()
    client.send_message(b"first")
    client.send_message(b"second")

    real_unframe = server._broker.unframe
    first_entered = threading.Event()
    release_first = threading.Event()
    seen = []
    seen_lock = threading.Lock()

    def gated_unframe(frame):
        with seen_lock:
            index = len(seen)
            seen.append(frame)
        if index == 0:
            # Announce that the first decrypt has begun, then wait so a second
            # reader has a chance to overtake us.
            first_entered.set()
            assert release_first.wait(timeout=5)
        return real_unframe(frame)

    server._broker.unframe = gated_unframe

    results = {}

    def reader(key):
        try:
            results[key] = server.recv_message()
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion
            results[key] = exc

    reader_a = threading.Thread(target=reader, args=("a",))
    reader_a.start()
    # Reader "a" has now read frame 0 and is parked inside the first unframe.
    assert first_entered.wait(timeout=5)

    reader_b = threading.Thread(target=reader, args=("b",))
    reader_b.start()
    # Give reader "b" the opportunity to read frame 1 and reach unframe (with the
    # bug) or block on the recv lock (once fixed).
    time.sleep(0.2)
    release_first.set()
    reader_a.join(timeout=5)
    reader_b.join(timeout=5)

    assert results.get("a") == b"first"
    assert results.get("b") == b"second"
