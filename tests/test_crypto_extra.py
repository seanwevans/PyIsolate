import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from pyisolate.broker.crypto import CTR_LIMIT, CryptoBroker
from pyisolate.libsodium import constant_compare


def _private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_bytes(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def make_broker(max_frame_len=4096):
    private_key = x25519.X25519PrivateKey.generate()
    peer_key = x25519.X25519PrivateKey.generate()
    return CryptoBroker(
        _private_bytes(private_key),
        _public_bytes(peer_key),
        max_frame_len=max_frame_len,
        role="client",
    )


def make_pair():
    priv_a = x25519.X25519PrivateKey.generate()
    priv_b = x25519.X25519PrivateKey.generate()
    max_len = 4096
    a = CryptoBroker(
        _private_bytes(priv_a),
        _public_bytes(priv_b),
        max_frame_len=max_len,
        role="client",
    )
    b = CryptoBroker(
        _private_bytes(priv_b),
        _public_bytes(priv_a),
        max_frame_len=max_len,
        role="server",
    )
    return a, b


def test_constant_compare_length_mismatch():
    assert not constant_compare(b"a", b"ab")


def test_unframe_short_frame():
    a, b = make_pair()
    with pytest.raises(ValueError):
        b.unframe(b"short")


def test_max_frame_len_rejects_zero():
    with pytest.raises(ValueError, match="max_frame_len must be at least 28 bytes"):
        make_broker(max_frame_len=0)


def test_max_frame_len_rejects_negative():
    with pytest.raises(ValueError, match="max_frame_len must be at least 28 bytes"):
        make_broker(max_frame_len=-1)


def test_max_frame_len_rejects_too_small():
    with pytest.raises(ValueError, match="max_frame_len must be at least 28 bytes"):
        make_broker(max_frame_len=27)


def test_max_frame_len_accepts_minimum_valid_limit():
    broker = make_broker(max_frame_len=28)
    assert broker._max_frame_len == 28


def test_max_frame_len_rejects_non_integer():
    with pytest.raises(ValueError, match="max_frame_len must be an integer"):
        make_broker(max_frame_len="28")


def test_unframe_frame_too_long():
    a, _ = make_pair()
    b = make_broker(max_frame_len=28)
    frame = a.frame(b"x")
    with pytest.raises(ValueError):
        b.unframe(frame)


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


def test_rotate_rejects_identical_key_material():
    priv_a = x25519.X25519PrivateKey.generate()
    priv_b = x25519.X25519PrivateKey.generate()
    a_priv, a_pub = _private_bytes(priv_a), _public_bytes(priv_a)
    b_priv, b_pub = _private_bytes(priv_b), _public_bytes(priv_b)
    a = CryptoBroker(a_priv, b_pub, role="client")
    b = CryptoBroker(b_priv, a_pub, role="server")

    # Re-rotating onto the same key material would reset the counters and reuse
    # (key, nonce) pairs, so it must be rejected -- and leave the broker intact.
    with pytest.raises(ValueError, match="fresh key material"):
        a.rotate(a_priv, b_pub)
    assert b.unframe(a.frame(b"still-works")) == b"still-works"


def test_key_rotation():
    a, b = make_pair()
    first = a.frame(b"first")
    assert b.unframe(first) == b"first"

    # Rotate to new key pair
    new_priv_a = x25519.X25519PrivateKey.generate()
    new_priv_b = x25519.X25519PrivateKey.generate()
    a.rotate(
        new_priv_a.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        new_priv_b.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    b.rotate(
        new_priv_b.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        new_priv_a.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )

    # After rotation counters start at zero
    second = a.frame(b"second")
    assert second[:12] == b"\x00" * 12
    assert b.unframe(second) == b"second"
