# SECURITY.md

## 1  Threat model

| Actor                                           | Capabilities                                                         | Goal                                                 |
| ----------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------- |
| **Guest attacker**                              | Executes arbitrary Python bytecode inside a sandbox sub‑interpreter. | • Escalate into supervisor or host OS                |
| • Read/modify data belonging to other sandboxes |                                                                      |                                                      |
| • Exhaust shared resources (CPU / RAM / I/O)    |                                                                      |                                                      |
| **Network adversary**                           | Can capture, replay, or inject broker frames over IPC/TCP.           | Hijack privileged RPCs; tamper or spoof audit trails |
| **Malicious extension author**                  | Crafts a wheel with native code to break isolation.                  | Load arbitrary ELF, bypass policies                  |

We **assume** the kernel and hardware are trusted and un‑compromised.  Kernel exploits or speculative‑execution side channels are *out of scope* (see §6).

---

## 2  Security guarantees

1. **Process containment** — Guest code cannot execute syscalls outside the eBPF allow‑list.
2. **Memory safety** — Each interpreter is hard‑capped to its RAM quota at the allocator level; no guest can corrupt another’s heap.
3. **Broker integrity & replay protection** — All control‑plane frames are AEAD‑sealed (X25519 → ChaCha20‑Poly1305) with strictly increasing counters; forged or replayed frames are dropped.
4. **Policy hot‑reload atomicity** — Policy updates are applied with a RCU‑style swap; a sandbox sees either the old *or* the new rule‑set, never a mix.
5. **Crash isolation** — Double‑faulting or segfault‑inducing code inside a sandboxed thread cannot bring down the supervisor (guarded by `pthread_sigmask` & alt‑stack guards).

Anything not listed above is *not* guaranteed.

---

## 3  Layered defence‑in‑depth

### 3.1 Kernel eBPF guards

* **LSM hooks** (`file_open`, `inode_unlink`, `socket_connect`) — path‑aware FS & net gating.
* **cgroup programs** — per‑sandbox memory (`cgroup/mem`), CPU (`perf‑event`) & bandwidth limits.
* **Tracepoint programs** — instant kill on `execve`, `ptrace`, `bpf()`, or other high‑risk syscalls.

### 3.2 CPython hardening

* **No‑GIL build** — removes the global interpreter lock; each sandbox runs on its own OS thread.
* **Per‑interpreter arenas** — allocator instances are never shared; freelists are local.
* **Stack canaries** — CPython compiled with `-fstack-protector-strong`.
* **Control‑flow integrity** — built with `-fsanitize=cfi` to detect code‑reuse attacks.
* **Builtin shrink‑wrap** — `__import__`, `open`, `ctypes`, `cffi`, `dlopen`, `mmap`, and `pickle` removed unless explicitly re‑enabled via policy.

### 3.3 Crypto‑sealed broker

* Noise‑like 1‑RTT handshake: `X25519` + optional `Kyber‑768` hybrid → HKDF‑SHA‑256.
* Per‑frame AEAD: `ChaCha20‑Poly1305` (96‑bit nonce, 16‑byte tag).
* 64‑bit monotone counter, stored in a lock‑free slab per channel; any rollback closes the channel.
* Keys can be rotated by repeating the handshake; counters reset on success.

### 3.4 Supervisor watchdog

* Reads a perf‑ring buffer from `resource_guard.bpf`; sends `SIGXCPU` or `SIGTERM` on quota breach.
* *Fail‑closed*: if the ringbuffer stalls → sandbox thread is cancelled.

---

## 4  Out of scope / known limitations

| Item                                                      | Rationale / Mitigation                                                            |
| --------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Kernel exploits**                                       | Run PyIsolate inside a VM or micro‑VM if attacker is assumed to have 0‑day power. |
| **Side‑channel leakage (L1/L3 cache, branch predictors)** | Use one process per tenant on highly sensitive workloads.                         |
| **Cooperative multithreading abuse**                      | Scheduler starvation possible; employ cgroup CPU quotas.                          |
| **Spectre v2**                                            | Mitigations inherit from host kernel; PyIsolate adds none.                        |

---

## 5  Supported platforms

* **Linux ≥ 6.6** (BPF‑LSM + BPF tokens).  CO‑RE objects ensure portability.
* **x86‑64 & aarch64** tested in CI.
* **cBPF‑only kernels** → fallback to Landlock + rlimit mode (reduced guarantees).

---

## 6  Secure build & supply chain

1. **Reproducible builds** — `nix flake` and Dockerfile produce identical SHA‑256 artefacts.
2. **Statically‑linked libsodium** — version pinned; signatures verified.
3. **eBPF bytecode** — compiled with `clang‑17`, stripped, SHA‑256 recorded in `bpf/manifest.lock`.
4. **GitHub Actions** — signed artefacts (`cosign`), provenance uploaded to Supply‑Chain Levels for Software Artifacts (SLSA) workflow.

---

## 7  Vulnerability disclosure

*Email:* `security@pyisolate.dev`  (GPG key `0xBEEFDEADCAFEBABE`).

We follow **RFC 9116**:
`├── /.well‑known/security.txt` with contact & encryption info.

| Severity                           | Response                              | Public disclosure         |
| ---------------------------------- | ------------------------------------- | ------------------------- |
| **Critical** (RCE, sandbox escape) | 24 h acknowledge, patch within 7 days | ≤ 72 h after fix released |
| **High**                           | 72 h acknowledge, 14 days patch       | after next minor release  |
| **Low / Informational**            | Best‑effort                           | Quarterly roll‑up         |

---

## 8  FAQ

> **Q: Why not seccomp only?**
> *A:* eBPF‑LSM lets us filter on path & arguments, not just syscall numbers.  See [Design](README.md#security‑model).

> **Q: Does crypto add noticeable latency?**
> *A:* Handshake ≈ 18 µs; per‑frame overhead < 400 ns on AVX2.

> **Q: Can I disable the broker and talk directly to the FS?**
> *A:* No. That defeats the trust boundary. Write a plugin that proxies the operation through approved opcodes.
