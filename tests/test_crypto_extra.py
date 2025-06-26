import pytest
from pyisolate.broker.crypto import CryptoBroker, CTR_LIMIT
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


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


def test_unframe_short_frame():
    a, b = make_pair()
    with pytest.raises(ValueError):
        b.unframe(b"short")


def test_tx_counter_overflow():
    a, _ = make_pair()
    a._tx_ctr = CTR_LIMIT
    a.frame(b"final")
    with pytest.raises(OverflowError):
        a.frame(b"boom")


def test_rx_counter_overflow():
    a, b = make_pair()
    b._rx_ctr = CTR_LIMIT + 1
    frame = a.frame(b"hi")
    with pytest.raises(OverflowError):
        b.unframe(frame)


def test_rx_final_frame_allowed():
    a, b = make_pair()
    a._tx_ctr = CTR_LIMIT
    b._rx_ctr = CTR_LIMIT
    frame = a.frame(b"edge")
    assert b.unframe(frame) == b"edge"
