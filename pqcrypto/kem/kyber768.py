"""Kyber-768 KEM stub built on X25519.

This is **not** a real post-quantum implementation; it merely provides the
minimal interface required by the tests. The functions mirror the API of the
`pqcrypto` package but internally leverage X25519 for key agreement.
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """Return a `(public, secret)` keypair."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pub, sk


def encrypt(peer_pk: bytes):
    """Encapsulate a shared secret to ``peer_pk``.

    Returns a tuple ``(ciphertext, shared_secret)`` where ``ciphertext`` is the
    ephemeral public key and ``shared_secret`` is the X25519 shared secret.
    """
    peer = x25519.X25519PublicKey.from_public_bytes(peer_pk)
    eph = x25519.X25519PrivateKey.generate()
    ct = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    ss = eph.exchange(peer)
    return ct, ss


def decrypt(ciphertext: bytes, secret_key: bytes):
    """Recover the shared secret from ``ciphertext`` using ``secret_key``."""
    sk = x25519.X25519PrivateKey.from_private_bytes(secret_key)
    peer = x25519.X25519PublicKey.from_public_bytes(ciphertext)
    return sk.exchange(peer)
