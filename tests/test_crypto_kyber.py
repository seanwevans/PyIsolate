import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

pq = pytest.importorskip("pqcrypto.kem.kyber768")

from pyisolate.broker.crypto import (
    CryptoBroker,
    kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
)


def make_pair():
    priv_a = x25519.X25519PrivateKey.generate()
    priv_b = x25519.X25519PrivateKey.generate()
    pk_a, sk_a = kyber_keypair()
    ct, ss_b = kyber_encapsulate(pk_a)
    ss_a = kyber_decapsulate(ct, sk_a)
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
        pq_secret=ss_a,
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
        pq_secret=ss_b,
    )
    return a, b


def test_hybrid_roundtrip():
    a, b = make_pair()
    msg = b"kyber"
    frame = a.frame(msg)
    assert b.unframe(frame) == msg
