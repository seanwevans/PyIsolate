# Broker Protocol

The supervisor and each sandbox communicate over an authenticated channel. Keys
are negotiated using X25519 and all frames are protected with
ChaCha20-Poly1305.

## Handshake

1. Each side generates an X25519 key pair.
2. Public keys are exchanged out of band.
3. A shared secret is derived via `X25519PrivateKey.exchange()`.
4. The secret feeds HKDF-SHA256 with `info=b"pyisolate-channel"` to produce the
   32 byte AEAD key.

## Framing

Frames are formatted as:

```
nonce (12 bytes little-endian counter) || ciphertext
```

The nonce is a monotonically increasing counter per direction. The same counter
serves as the ChaCha20-Poly1305 nonce. Frames received with a counter that does
not match the expected value are rejected to prevent replay.

## Security notes

* Nonces are counters starting at zero to guarantee uniqueness.
* HKDF provides key separation between channels.
* Empty associated data is used by default but can be extended in future
  revisions.
