# SECURITY.md

> Canonical boundary definition: see [`docs/threat-model.md`](docs/threat-model.md) (normative baseline).

**The security boundary depends on the backend you choose.** This is the single
most important thing to understand before deploying PyIsolate:

- `backend="subinterpreter"` (the default) is an **execution cell**, not a
  boundary against hostile Python. Run only trusted code in it.
- `backend="process"` is the **boundary mode**: the guest runs in a separate OS
  process confined in depth by the kernel.
- `backend="microvm"` is reserved and not yet implemented.

## 1  Threat model

| Actor | Capabilities | Goal |
| ----- | ------------ | ---- |
| **Guest attacker** | Executes arbitrary Python bytecode inside a sandbox. | Escalate into the supervisor or host OS; read/modify other sandboxes' data; exhaust shared CPU/RAM/I/O. |
| **Network adversary** | Can capture, replay, or inject broker frames over IPC/TCP. | Hijack privileged RPCs; tamper with or spoof audit trails. |
| **Malicious extension author** | Crafts a wheel with native code to break isolation. | Load arbitrary ELF, bypass policies. |

We **assume** the kernel and hardware are trusted and un-compromised. Kernel
exploits and speculative-execution side channels are *out of scope* (see §4).

---

## 2  Security guarantees

### Authoritative boundary statement

The guarantees below apply to **`backend="process"`**. The sub-interpreter
backend provides none of them against adversarial Python — its restricted
builtins and import allow-list are bypassable guardrails, not a boundary.

Each kernel layer is applied **best-effort** and recorded in the sandbox's
confinement report; a host that lacks a layer keeps the others. In **hardened**
rollout mode, a required-but-unavailable layer fails closed rather than degrading
silently.

1. **Address-space isolation** — Guest code runs in a separate process and cannot
   read or corrupt supervisor or sibling-sandbox memory. In-process Python
   escapes (e.g. recovering the real `__import__` via `object.__subclasses__()`)
   stay inside the guest process.
2. **Syscall reduction** — `PR_SET_NO_NEW_PRIVS` plus a seccomp deny-list
   (`SECCOMP_RET_KILL_PROCESS`) kills the guest on dangerous syscalls: `execve`,
   `ptrace`, mount/namespace operations, `bpf`, kernel-module load,
   `process_vm_readv`/`writev`, and others. x86-64 Linux. This is a robust
   deny-list, **not** a proof that only a fixed syscall allow-list is reachable.
3. **Filesystem policy** — Landlock confines the guest to the policy's read/write
   paths, on kernels that support Landlock.
4. **Network-egress policy** — On Landlock ABI >= 4 (Linux 6.7+) the policy's TCP
   allow-list is mapped to allowed `connect()` ports and the kernel denies egress
   to every other port. Landlock keys network rules on port, not address, so this
   is a coarse kernel backstop beneath the userspace host:port guard; it is
   applied only when every allow-listed destination carries a parseable port.
5. **Coarse capability gating** — A per-cgroup eBPF/LSM `deny_mask` denies whole
   capability classes (process creation, ptrace/mount/bpf, and filesystem or
   network when the policy grants nothing in that class), on kernels with
   BPF-LSM. This is coarse: it cannot express per-path allow-lists — that is
   Landlock's job (§2.3) and the broker's.
6. **Broker integrity & replay protection** — Control-plane frames are AEAD-sealed
   (X25519 → HKDF-SHA-256 → ChaCha20-Poly1305, optional Kyber-768 hybrid) with a
   strictly increasing per-direction counter; forged, reordered, or replayed
   frames are rejected.
7. **Crash isolation** — A crash in a guest process cannot bring down the
   supervisor.

Resource quotas (CPU/RAM/I/O) are enforced by `rlimit` and cgroup v2 controls
where available. Anything not listed above is *not* guaranteed.

---

## 3  Layered defence-in-depth

### 3.1 Process boundary (`backend="process"`)

The guest runs in a fresh interpreter in its own OS process, speaking a
length-framed JSON protocol to the supervisor. Values crossing the boundary are
JSON only — the supervisor never unpickles bytes produced by untrusted guest
code. Confinement is applied before any guest code runs, in order:
`no_new_privs` → `rlimit` → Landlock → seccomp.

### 3.2 Kernel enforcement

* **seccomp** deny-list — kills the process on high-risk syscalls; inherited
  across `fork`/`clone` and irremovable once `no_new_privs` is set.
* **Landlock** — filesystem access restricted to the policy's paths, and (ABI
  >= 4) TCP `connect()` restricted to the policy's allow-listed ports (kernels
  with Landlock support).
* **eBPF/LSM** — a per-cgroup `deny_mask` on `file_open`, `socket_connect`,
  `task_alloc`, `bprm_check_security`, `ptrace`, `sb_mount`, and `bpf` hooks,
  keyed by the sandbox's cgroup id (kernels with BPF-LSM).
* **cgroup v2 / rlimit** — CPU, memory, and address-space caps; a supervisor
  watchdog reads the `resource_guard` ring buffer and terminates sandboxes on
  quota breach (fail-closed if the ring stalls).

### 3.3 Crypto-sealed broker

* X25519 key agreement (optional Kyber-768 hybrid) → HKDF-SHA-256, direction-
  separated keys.
* Per-frame ChaCha20-Poly1305 (96-bit counter nonce, 16-byte tag).
* Strictly increasing per-direction counter; a rollback or gap rejects the frame.
* Keys rotate by repeating the handshake; counters reset on success.

### 3.4 Userspace guards (both backends)

Import allow-listing and blocked builtins (`open`, `eval`, `exec`, …) are applied
in every backend. Treat them as defense-in-depth and ergonomics, **not** as the
boundary: in the sub-interpreter backend they are the *only* layer and are
bypassable.

### 3.5 Roadmap (not currently guaranteed)

The following are targets, not present guarantees, and must not be relied on:
no-GIL/free-threaded per-sandbox parallelism, per-interpreter allocator arenas,
CPython built with `-fstack-protector-strong`/`-fsanitize=cfi`, path-aware
(rather than coarse) eBPF filesystem/network matching, and the microVM backend.

---

## 4  Out of scope / known limitations

| Item | Rationale / mitigation |
| ---- | ---------------------- |
| **Hostile Python under `backend="subinterpreter"`** | Not a boundary; use `backend="process"` or an external VM/container. |
| **Hostile native extensions** (`ctypes`, `cffi`, `dlopen`, native wheels) | Deny by default; only allow vetted code. Native code can subvert interpreter-level assumptions. |
| **Kernel exploits / verifier bypass** | Run inside a VM or microVM if the attacker is assumed to have 0-day power. |
| **Side-channel leakage** (cache, branch predictor, Spectre) | Use one process per tenant on highly sensitive workloads; PyIsolate adds no microarchitectural mitigations. |
| **Supervisor compromise** | The model is broken for all sandboxes in that process; no recovery guarantee. |
| **Missing kernel features** | Each confinement layer degrades independently; use hardened rollout mode to fail closed instead. |

---

### Isolation hierarchy (recommended interpretation)

1. **Sub-interpreter** — execution cell only; not a boundary against hostile code.
2. **Thread** — scheduling/accounting unit.
3. **Process + kernel policy** (`backend="process"`) — the production security
   boundary.
4. **Container / microVM** — stronger boundary and recommended for hostile
   multi-tenant environments.

---

## 5  Supported platforms

* **seccomp deny-list**: x86-64 Linux.
* **Landlock**: Linux kernels that expose the Landlock ABI (skipped otherwise).
* **eBPF/LSM `deny_mask`**: kernels with BPF-LSM and cgroup v2.
* Where a feature is unavailable, that layer is skipped and recorded in the
  confinement report; the remaining layers still apply.

Use `python -m pyisolate.conformance --grade` (or `pyisolate doctor --grade`) to
see which guarantees are actually active on a given host.

---

## 6  Secure build & supply chain

`pyisolate-doctor` records installation provenance (Python build hash, no-GIL
status, kernel features, BPF toolchain availability, deterministic-wheel policy
flags). Reproducible-build, artifact-signing, and eBPF-bytecode-pinning
workflows are roadmap items; do not assume signed or reproducible artifacts
unless your own pipeline provides them.

---

## 7  Vulnerability disclosure

Please report suspected vulnerabilities through the repository's private security
advisory process on GitHub rather than a public issue. Include a minimal
reproduction and the affected backend and kernel features. We aim to acknowledge
promptly and to disclose after a fix is available.

---

## 8  FAQ

> **Q: Why not seccomp only?**
> *A:* seccomp filters syscall numbers/arguments but not paths. Landlock adds
> path-scoped filesystem enforcement, and eBPF/LSM adds per-cgroup capability
> gating. The layers are complementary.

> **Q: Is the sub-interpreter backend safe for untrusted code?**
> *A:* No. Use `backend="process"`, ideally inside a VM or microVM for hostile
> multi-tenant workloads.

> **Q: Can I disable the broker and talk directly to the FS?**
> *A:* No. That defeats the trust boundary. Route the operation through an
> approved broker capability.
