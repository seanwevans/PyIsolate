import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pyisolate.broker.crypto import CryptoBroker, handshake


def make_pair():
    priv_a = x25519.X25519PrivateKey.generate()
    priv_b = x25519.X25519PrivateKey.generate()
    max_len = 4096
    a = CryptoBroker(
        priv_a.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        priv_b.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        max_frame_len=max_len,
    )
    b = CryptoBroker(
        priv_b.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        priv_a.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        max_frame_len=max_len,
    )
    return a, b


def test_roundtrip():
    a, b = make_pair()
    msg = b"secret"
    frame = a.frame(msg)
    assert b.unframe(frame) == msg


def test_replay_detection():
    a, b = make_pair()
    frame = a.frame(b"hi")
    b.unframe(frame)
    with pytest.raises(ValueError):
        b.unframe(frame)


def test_out_of_order():
    a, b = make_pair()
    dropped = a.frame(b"one")
    later = a.frame(b"two")
    with pytest.raises(ValueError):
        b.unframe(later)
    # deliver the dropped frame then the next
    assert b.unframe(dropped) == b"one"
    assert b.unframe(later) == b"two"


def test_handshake_helper():
    priv_b = x25519.X25519PrivateKey.generate()
    pub_b = priv_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    pub_a, broker_a = handshake(pub_b)
    broker_b = CryptoBroker(
        priv_b.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        pub_a,
        max_frame_len=4096,
    )

    msg = b"hi"
    assert broker_b.unframe(broker_a.frame(msg)) == msg


def test_concurrent_roundtrip():
    a, b = make_pair()
    results = [None] * 100

    def worker(i: int) -> None:
        msg = f"hi{i}".encode()
        frame = a.frame(msg)
        results[i] = b.unframe(frame)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results == [f"hi{i}".encode() for i in range(100)]


def test_concurrent_rotate():
    a, b = make_pair()
    new_priv_a = x25519.X25519PrivateKey.generate()
    new_priv_b = x25519.X25519PrivateKey.generate()
    new_pub_a = new_priv_a.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    new_pub_b = new_priv_b.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_a_bytes = new_priv_a.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_b_bytes = new_priv_b.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    threads = []
    for _ in range(10):
        threads.append(
            threading.Thread(target=a.rotate, args=(priv_a_bytes, new_pub_b))
        )
        threads.append(
            threading.Thread(target=b.rotate, args=(priv_b_bytes, new_pub_a))
        )

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    msg = b"rotated"
    assert b.unframe(a.frame(msg)) == msg
