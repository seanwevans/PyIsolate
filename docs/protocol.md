# Broker Protocol

PyIsolate treats the **trusted control plane** and the **untrusted workload plane**
as separate systems.

- **Trusted control plane**: supervisor, broker, metrics, and policy engine.
- **Untrusted workload plane**: guest code running in sandbox threads.

Crossings are intentionally minimal and explicit.

## Plane crossings

Only structured messages are allowed across the queue boundary.
`pyisolate.runtime.protocol` defines the request vocabulary:

- `ExecRequest(source)`
- `CallRequest(target, args, kwargs)`
- `AttachCgroupRequest(old_path)`
- `StopRequest()`
- `ControlRequest(op, capability, payload)`

This replaces ambient tuple/string payloads with typed requests.

## Capability handles

Control operations must carry an explicit `CapabilityHandle(kind, subject)`.
The supervisor maps:

- canonical `ROOT` capability -> `CapabilityHandle(kind="root", subject=<op>)`
- valid policy token -> `CapabilityHandle(kind="policy-token", subject=<op>)`

No other callers can execute privileged control actions.

## Authenticated control operations

`Supervisor.reload_policy()` now authorizes as a control request before it can
trigger BPF hot-reload (`op="policy.reload"`).

Unauthenticated operations are rejected with `PolicyAuthError`.

## Cryptographic channel

The supervisor and each sandbox communicate over an authenticated channel.
Keys are negotiated using X25519 and, if available, a Kyber‑768
key‑encapsulation mechanism. The resulting secret feeds HKDF and all
frames are protected with ChaCha20-Poly1305.

### Handshake

1. Each side generates an X25519 key pair.
2. Public keys are exchanged out of band.
3. A shared secret is derived via `X25519PrivateKey.exchange()`.
4. The secret feeds HKDF-SHA256 with `info=b"pyisolate-channel"` to produce the
   32 byte AEAD key.
5. The helper `pyisolate.broker.crypto.handshake()` wraps these steps and
   returns `(public_key, broker)`.
6. Keys can be rotated by repeating steps 1‑5; counters reset to zero after a
   successful rotation.

### Framing

Frames are formatted as:

```
nonce (12 bytes little-endian counter) || ciphertext
```

The nonce is a monotonically increasing counter per direction. The same counter
serves as the ChaCha20-Poly1305 nonce. Frames received with a counter that does
not match the expected value are rejected to prevent replay.

### Security notes

- Nonces are counters starting at zero to guarantee uniqueness.
- HKDF provides key separation between channels.
- Empty associated data is used by default but can be extended in future
  revisions.
