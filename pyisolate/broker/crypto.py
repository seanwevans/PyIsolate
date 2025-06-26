"""Authenticated framing helpers for the broker channel."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CTR_LIMIT = 0xFFFFFFFFFFFFFFFFFFFF  # 2^96 - 1


class CryptoBroker:
    """Broker side of the authenticated channel."""

    def __init__(self, private_key: bytes, peer_key: bytes):
        priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
        try:
            pub = x25519.X25519PublicKey.from_public_bytes(peer_key)
        except Exception as exc:  # maintain constant-time failure path
            priv.exchange(x25519.X25519PrivateKey.generate().public_key())
            raise ValueError("invalid peer key") from exc
        shared = priv.exchange(pub)
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


def handshake(peer_key: bytes, *, private_key: bytes | None = None) -> tuple[bytes, CryptoBroker]:
    """Perform a one-shot X25519 handshake and return ``(public_key, broker)``.

    If ``private_key`` is ``None``, a fresh keypair is generated. The returned
    ``public_key`` should be sent to the peer, while ``broker`` is ready for
    authenticated framing.
    """

    if private_key is None:
        priv_obj = x25519.X25519PrivateKey.generate()
        priv_bytes = priv_obj.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    else:
        priv_bytes = private_key
        priv_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)

    pub_bytes = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    broker = CryptoBroker(priv_bytes, peer_key)
    return pub_bytes, broker
