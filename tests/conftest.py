import sys
import types

# Provide a minimal stub for the 'cryptography' package when it is missing.


def pytest_configure(config):
    try:
        import cryptography  # pragma: no cover - real lib present
        _ = cryptography
    except ModuleNotFoundError:  # pragma: no cover - fallback path
        crypto = types.ModuleType('cryptography')
        hazmat = types.ModuleType('cryptography.hazmat')
        primitives = types.ModuleType('cryptography.hazmat.primitives')
        hashes = types.ModuleType('cryptography.hazmat.primitives.hashes')
        serialization = types.ModuleType('cryptography.hazmat.primitives.serialization')
        asymmetric = types.ModuleType('cryptography.hazmat.primitives.asymmetric')
        x25519 = types.ModuleType('cryptography.hazmat.primitives.asymmetric.x25519')
        ciphers = types.ModuleType('cryptography.hazmat.primitives.ciphers')
        aead = types.ModuleType('cryptography.hazmat.primitives.ciphers.aead')
        kdf = types.ModuleType('cryptography.hazmat.primitives.kdf')
        hkdf = types.ModuleType('cryptography.hazmat.primitives.kdf.hkdf')

        class DummySHA256:
            pass

        class DummyHKDF:
            def __init__(self, algorithm=None, length=None, salt=None, info=None):
                pass

            def derive(self, shared):
                return b"x" * 32

        class DummyPrivateKey:
            def __init__(self, key: bytes):
                self.key = key

            @classmethod
            def from_private_bytes(cls, data: bytes):
                return cls(data)

            @classmethod
            def generate(cls):
                return cls(b"\x00" * 32)

            def exchange(self, peer: 'DummyPublicKey') -> bytes:  # type: ignore[name-defined]
                return b"shared" + peer.key

            def public_key(self) -> 'DummyPublicKey':  # type: ignore[name-defined]
                return DummyPublicKey(self.key)

            def private_bytes(self, *a, **kw):
                return self.key

        class DummyPublicKey:
            def __init__(self, key: bytes):
                self.key = key

            @classmethod
            def from_public_bytes(cls, data: bytes):
                return cls(data)

            def public_bytes(self, *a, **kw):
                return self.key

        class DummyChaCha20Poly1305:
            def __init__(self, key: bytes):
                pass

            def encrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
                return data[::-1]

            def decrypt(self, nonce: bytes, data: bytes, aad: bytes) -> bytes:
                return data[::-1]

        serialization.Encoding = types.SimpleNamespace(Raw=0)
        serialization.PublicFormat = types.SimpleNamespace(Raw=0)
        serialization.PrivateFormat = types.SimpleNamespace(Raw=0)
        serialization.NoEncryption = type('NoEncryption', (), {})

        hashes.SHA256 = DummySHA256
        x25519.X25519PrivateKey = DummyPrivateKey
        x25519.X25519PublicKey = DummyPublicKey
        aead.ChaCha20Poly1305 = DummyChaCha20Poly1305
        hkdf.HKDF = DummyHKDF

        crypto.hazmat = hazmat
        hazmat.primitives = primitives
        primitives.hashes = hashes
        primitives.serialization = serialization
        primitives.asymmetric = asymmetric
        primitives.ciphers = ciphers
        primitives.kdf = kdf
        asymmetric.x25519 = x25519
        ciphers.aead = aead
        kdf.hkdf = hkdf

        modules = {
            'cryptography': crypto,
            'cryptography.hazmat': hazmat,
            'cryptography.hazmat.primitives': primitives,
            'cryptography.hazmat.primitives.hashes': hashes,
            'cryptography.hazmat.primitives.serialization': serialization,
            'cryptography.hazmat.primitives.asymmetric': asymmetric,
            'cryptography.hazmat.primitives.asymmetric.x25519': x25519,
            'cryptography.hazmat.primitives.ciphers': ciphers,
            'cryptography.hazmat.primitives.ciphers.aead': aead,
            'cryptography.hazmat.primitives.kdf': kdf,
            'cryptography.hazmat.primitives.kdf.hkdf': hkdf,
        }
        sys.modules.update(modules)
