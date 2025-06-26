"""Authenticated framing helpers for the broker channel."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:  # Optional post-quantum KEM
    from pqcrypto.kem import kyber768

    HAVE_KYBER = True
except Exception:  # pragma: no cover - library optional
    HAVE_KYBER = False

CTR_LIMIT = 0xFFFFFFFFFFFFFFFFFFFF  # 2^96 - 1


def kyber_keypair() -> tuple[bytes, bytes]:
    """Generate a Kyber-768 key pair."""
    if not HAVE_KYBER:
        raise RuntimeError("Kyber library not available")
    pk, sk = kyber768.generate_keypair()
    return bytes(pk), bytes(sk)


def kyber_encapsulate(peer_pk: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret to ``peer_pk``."""
    if not HAVE_KYBER:
        raise RuntimeError("Kyber library not available")
    ct, ss = kyber768.encrypt(peer_pk)
    return bytes(ct), bytes(ss)


def kyber_decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
    """Recover the shared secret from ``ciphertext``."""
    if not HAVE_KYBER:
        raise RuntimeError("Kyber library not available")
    return bytes(kyber768.decrypt(ciphertext, secret_key))


class CryptoBroker:
    """Broker side of the authenticated channel."""

    def __init__(self, private_key: bytes, peer_key: bytes, *, pq_secret: bytes | None = None):
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        pub = x25519.X25519PublicKey.from_public_bytes(peer_key)
        shared = priv.exchange(pub)
        if pq_secret is not None:
            shared += pq_secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"pyisolate-channel",
        )
        self._key = hkdf.derive(shared)
        self.public_key = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._aead = ChaCha20Poly1305(self._key)
        self._tx_ctr = 0
        self._rx_ctr = 0

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(12, "little")

    def frame(self, data: bytes) -> bytes:
        """Encrypt and frame ``data`` using the send counter."""
        if self._tx_ctr > CTR_LIMIT:
            raise OverflowError("send counter overflow")
        nonce = self._nonce(self._tx_ctr)
        self._tx_ctr += 1
        return nonce + self._aead.encrypt(nonce, data, b"")

    def unframe(self, data: bytes) -> bytes:
        """Validate counter, decrypt, and return plaintext."""
        if self._rx_ctr > CTR_LIMIT:
            raise OverflowError("receive counter overflow")
        # Maintain constant-time failure handling by always invoking ``decrypt``
        # even when the frame is malformed or the counter is unexpected.
        if len(data) < 12:
            nonce = b"\x00" * 12
            try:
                self._aead.decrypt(nonce, b"\x00" * 16, b"")
            except Exception:
                pass
            raise ValueError("invalid frame")

        nonce = data[:12]
        ctr = int.from_bytes(nonce, "little")
        if ctr != self._rx_ctr:
            try:
                self._aead.decrypt(nonce, data[12:], b"")
            except Exception:
                pass
            raise ValueError("replay detected")

        self._rx_ctr += 1
        return self._aead.decrypt(nonce, data[12:], b"")
