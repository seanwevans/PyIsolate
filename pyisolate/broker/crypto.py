"""Authenticated framing helpers for the broker channel.

``CryptoBroker`` encrypts/decrypts AEAD frames and limits the maximum
incoming frame size via the ``max_frame_len`` constructor argument.
Frames exceeding this bound raise :class:`ValueError` during
``unframe`` to avoid unbounded allocations.
"""

from __future__ import annotations

from threading import Lock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..libsodium import constant_compare

try:  # Optional post-quantum KEM
    from pqcrypto.kem import kyber768

    HAVE_KYBER = True
except Exception:  # pragma: no cover - library optional
    HAVE_KYBER = False

CTR_LIMIT = (1 << 96) - 1  # 96-bit nonce space (counter.to_bytes(12, ...))
DEFAULT_MAX_FRAME_LEN = 1 << 20  # 1 MiB
MIN_FRAME_LEN = 12 + 16  # nonce + ChaCha20-Poly1305 tag


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
    """Broker side of the authenticated channel.

    ``CryptoBroker`` instances are safe for concurrent use from multiple
    threads; counter and key updates are protected by an internal lock.
    """

    _tx_ctr: int
    _rx_ctr: int

    def __init__(
        self,
        private_key: bytes,
        peer_key: bytes,
        *,
        pq_secret: bytes | None = None,
        max_frame_len: int = DEFAULT_MAX_FRAME_LEN,
        role: str = "client",
    ):
        self._lock = Lock()
        if type(max_frame_len) is not int:
            raise ValueError("max_frame_len must be an integer")
        if max_frame_len < MIN_FRAME_LEN:
            raise ValueError("max_frame_len must be at least 28 bytes")
        self._max_frame_len = max_frame_len
        self._role = self._validate_role(role)
        self.rotate(private_key, peer_key, pq_secret=pq_secret)

    @property
    def max_frame_len(self) -> int:
        """Maximum accepted frame size in bytes (including nonce and tag)."""
        return self._max_frame_len

    @staticmethod
    def _nonce(counter: int) -> bytes:
        return counter.to_bytes(12, "little")

    @staticmethod
    def _validate_role(role: str) -> str:
        if role not in {"client", "server"}:
            raise ValueError('role must be "client" or "server"')
        return role

    @staticmethod
    def _derive_key(shared: bytes, info: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
        )
        return hkdf.derive(shared)

    def rotate(
        self,
        private_key: bytes,
        peer_key: bytes,
        *,
        pq_secret: bytes | None = None,
        role: str | None = None,
    ) -> None:
        """Derive new directional AEAD keys and reset counters."""
        with self._lock:
            if role is not None:
                self._role = self._validate_role(role)
            priv = x25519.X25519PrivateKey.from_private_bytes(private_key)
            try:
                pub = x25519.X25519PublicKey.from_public_bytes(peer_key)
            except Exception as exc:  # maintain constant-time failure path
                priv.exchange(x25519.X25519PrivateKey.generate().public_key())
                raise ValueError("invalid peer key") from exc
            shared = priv.exchange(pub)
            if pq_secret is not None:
                shared += pq_secret
            client_to_server = self._derive_key(
                shared, b"pyisolate-channel client->server"
            )
            server_to_client = self._derive_key(
                shared, b"pyisolate-channel server->client"
            )
            if self._role == "client":
                new_tx_key = client_to_server
                new_rx_key = server_to_client
            else:
                new_tx_key = server_to_client
                new_rx_key = client_to_server
            # ``rotate`` zeroes the send/receive counters. Re-deriving the
            # current keys after frames have been exchanged would restart the
            # nonce sequence and reuse (key, nonce) pairs -- catastrophic for
            # ChaCha20-Poly1305 (and a replay window on the receive side). A
            # genuine rotation supplies fresh key material; resetting onto the
            # same keys before any frame is exchanged is harmless.
            prev_tx_key = getattr(self, "_tx_key", None)
            if (
                prev_tx_key is not None
                and (self._tx_ctr > 0 or self._rx_ctr > 0)
                and constant_compare(new_tx_key, prev_tx_key)
            ):
                raise ValueError(
                    "rotate requires fresh key material once frames have been "
                    "exchanged; identical keys would reuse nonces"
                )
            self._tx_key = new_tx_key
            self._rx_key = new_rx_key
            self.public_key = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._tx_aead = ChaCha20Poly1305(self._tx_key)
            self._rx_aead = ChaCha20Poly1305(self._rx_key)
            self._tx_ctr = 0
            self._rx_ctr = 0

    def frame(self, data: bytes) -> bytes:
        """Encrypt and frame ``data`` using the send counter."""
        with self._lock:
            if self._tx_ctr > CTR_LIMIT:
                raise OverflowError("send counter overflow")
            nonce = self._nonce(self._tx_ctr)
            self._tx_ctr += 1
            return nonce + self._tx_aead.encrypt(nonce, data, b"")

    def unframe(self, data: bytes) -> bytes:
        """Validate counter, decrypt, and return plaintext."""
        with self._lock:
            if self._rx_ctr > CTR_LIMIT:
                raise OverflowError("receive counter overflow")
            if len(data) > self._max_frame_len:
                nonce = b"\x00" * 12
                try:
                    self._rx_aead.decrypt(nonce, b"\x00" * 16, b"")
                except Exception:
                    pass
                raise ValueError("frame too large")
            # Maintain constant-time failure handling by always invoking ``decrypt``
            # even when the frame is malformed or the counter is unexpected.
            if len(data) < 12:
                nonce = b"\x00" * 12
                try:
                    self._rx_aead.decrypt(nonce, b"\x00" * 16, b"")
                except Exception:
                    pass
                raise ValueError("invalid frame")

            nonce = data[:12]
            expected_nonce = self._nonce(self._rx_ctr)
            if not constant_compare(nonce, expected_nonce):
                try:
                    self._rx_aead.decrypt(nonce, data[12:], b"")
                except Exception:
                    pass
                raise ValueError("replay detected")

            try:
                plaintext = self._rx_aead.decrypt(nonce, data[12:], b"")
            except Exception:
                raise ValueError("decryption failed") from None
            self._rx_ctr += 1

            return plaintext


def handshake(
    peer_key: bytes,
    *,
    private_key: bytes | None = None,
    pq_secret: bytes | None = None,
    role: str = "client",
) -> tuple[bytes, CryptoBroker]:
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

    broker = CryptoBroker(priv_bytes, peer_key, pq_secret=pq_secret, role=role)
    return pub_bytes, broker
