# PyIsolate Threat Model (Frozen)

**Status:** Normative, frozen baseline  
**Effective date:** April 21, 2026  
**Applies to:** `main` runtime (`pyisolate.supervisor`, `pyisolate.runtime.thread`, `pyisolate.bpf.*`, `pyisolate.broker.*`)

This document is the single source of truth for what PyIsolate **does** and **does not** defend against.
If a guarantee is not listed here, it is **not** guaranteed.

---

## Security boundary summary

PyIsolate is a **single-process sandboxing system** that uses:

- CPython sub-interpreters for workload separation.
- eBPF/LSM/cgroup controls for syscall, filesystem, network, and resource policy enforcement.
- A brokered control/data path with authenticated encryption and replay counters.

PyIsolate provides **defense in depth**, not a cryptographic VM boundary.

---

## Explicit answers (hard yes/no)

## 1) Hostile Python code

**Answer: DEFENDED (within stated limits).**

PyIsolate is designed to run arbitrary, hostile Python bytecode and constrain it with policy:

- restricted builtins/import surface,
- broker-mediated privileged operations,
- kernel-enforced policy for FS/network/syscalls,
- per-sandbox quotas and watchdog enforcement.

**Not covered under this item:** kernel 0-days, CPU side channels, and any path that depends on loading untrusted native code.

---

## 2) Hostile native extensions

**Answer: NOT DEFENDED by default.**

If untrusted C/C++/Rust extension modules (native wheels, `ctypes`, `cffi`, `dlopen` paths) are allowed, they can violate interpreter-level assumptions and may reach host compromise depending on kernel/runtime vulnerabilities.

PyIsolate's position is:

- treat native extension loading as a **high-risk capability**,
- deny by default in hardened policies,
- only allow vetted/signed extensions in trusted deployments.

So: PyIsolate is **not** a safe environment for arbitrary hostile native extensions.

---

## 3) Host escape

**Answer: PARTIALLY DEFENDED.**

PyIsolate attempts to prevent sandbox-to-host escape via kernel policy (LSM/cgroup/eBPF) and broker mediation.

However, host escape is still possible if assumptions fail, including:

- kernel vulnerability / verifier bypass,
- privileged misconfiguration,
- unsafe allowance of native code.

Therefore, PyIsolate is **not** equivalent to a hardware VM isolation boundary. For high-assurance multitenancy, run inside a VM or microVM.

---

## 4) Data exfiltration

**Answer: DEFENDED ONLY BY EXPLICIT POLICY; otherwise NOT DEFENDED.**

PyIsolate can block exfiltration channels (filesystem, network, broker opcodes) when policy denies them.

If policy permits outbound network, file reads, or broker operations that expose secrets, PyIsolate does not prevent exfiltration through those allowed channels.

So the guarantee is conditional:

- **Denied channels in policy:** defended.
- **Allowed channels in policy:** not defended.

---

## 5) Noisy-neighbor resource abuse

**Answer: DEFENDED (best-effort, strong operational controls).**

PyIsolate includes cgroup/eBPF accounting and watchdog-triggered enforcement for CPU and memory quotas, intended to prevent one sandbox from starving others.

Residual risk remains for scheduler pathologies and extreme host-level contention, but resource abuse is an explicit defended objective.

---

## 6) Cross-sandbox interference

**Answer: PARTIALLY DEFENDED.**

PyIsolate aims to prevent direct cross-sandbox access using per-sandbox policy, channels, and kernel controls.

It does **not** claim complete protection against all side channels (cache timing, branch predictor effects, shared-kernel leakage classes).

So:

- direct unauthorized read/write via normal APIs: defended,
- microarchitectural/side-channel leakage: not defended.

---

## 7) Supervisor compromise

**Answer: NOT DEFENDED as a recovery guarantee.**

If the supervisor is compromised, the security model is considered broken for all sandboxes in that process.

PyIsolate includes hardening to reduce likelihood (broker authentication, policy controls, watchdogs), but does not guarantee continued sandbox security after supervisor compromise.

---

## Assumptions

These assumptions must hold for the defended claims above:

1. Trusted host kernel and hardware (no active kernel compromise).
2. Correct deployment of required eBPF/LSM/cgroup features.
3. Hardened policy configuration (especially denying untrusted native extension paths).
4. Supervisor process integrity is maintained.

If any assumption is false, guarantees degrade accordingly.

---

## Non-goals / out of scope

PyIsolate does not claim to defend against:

- kernel 0-day exploitation,
- speculative/microarchitectural side channels,
- physical attacks,
- compromise caused by intentionally trusted privileged plugins/components,
- confidentiality/integrity after supervisor compromise.

---

## Change control

This threat model is frozen as of **April 21, 2026**.
Any semantic change to defended/not-defended status requires:

1. an explicit update to this file,
2. corresponding updates to `SECURITY.md` and user-facing docs,
3. a release note entry calling out the boundary change.
