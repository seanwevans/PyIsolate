import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pyisolate.broker.crypto import CryptoBroker


def make_pair():
    priv_a = x25519.X25519PrivateKey.generate()
    priv_b = x25519.X25519PrivateKey.generate()
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
