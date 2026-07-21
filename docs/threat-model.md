# PyIsolate Threat Model (Frozen)

**Status:** Normative baseline  
**Effective date:** July 20, 2026 (supersedes April 21, 2026)  
**Applies to:** `main` runtime (`pyisolate.supervisor`, `pyisolate.runtime.thread`, `pyisolate.runtime.process_backend`, `pyisolate.runtime.confine`, `pyisolate.runtime.landlock`, `pyisolate.bpf.*`, `pyisolate.broker.*`)

This document is the single source of truth for what PyIsolate **does** and **does not** defend against.
If a guarantee is not listed here, it is **not** guaranteed.

---

## The boundary depends on the backend

PyIsolate's security posture is **not uniform** across backends. Read every
answer below as conditional on the backend you select.

- **`backend="subinterpreter"`** (the default) is an *execution cell*, **not** a
  security boundary against hostile Python. Guest code runs in a sub-interpreter
  in the supervisor's own process; the restricted builtins and import allow-list
  are ergonomic guardrails that adversarial Python can bypass (for example by
  walking `object.__subclasses__()` to recover an unrestricted `__import__` and
  reaching the real `os`/`open`). Use it for trusted code, or for scheduling and
  organization — not to contain code you do not trust.

- **`backend="process"`** is the boundary mode. The guest runs in a **separate
  OS process** (so those in-process escapes can no longer touch supervisor
  memory), confined in depth by the host kernel:
  - `PR_SET_NO_NEW_PRIVS` + a **seccomp** deny-list that kills the process on
    dangerous syscalls (`execve`, `ptrace`, mount/namespace ops, `bpf`, kernel
    module load, `process_vm_*`, …) — x86-64 Linux;
  - **Landlock** filesystem rules derived from policy, where the kernel supports
    it, plus **Landlock TCP-egress** rules that allow-list the connect ports in
    the policy (Landlock ABI >= 4 / Linux 6.7+; keyed on port, not address);
  - a **coarse per-cgroup eBPF/LSM deny-mask** (deny whole capability classes),
    where BPF-LSM is available;
  - `rlimit` and cgroup resource caps.

Each kernel layer is applied **best-effort** and recorded in the sandbox's
confinement report; a host missing a layer keeps the others. In **hardened**
rollout mode a required-but-unavailable layer fails closed. Even at full
strength this is **defense in depth, not a hardware VM boundary** — for
high-assurance multitenancy, run one sandbox per process inside a VM or microVM.

- **`backend="microvm"`** is the reserved hardware-VM boundary. The supervisor
  probes for a supported VMM (Firecracker, Cloud Hypervisor, QEMU) and an
  accessible `/dev/kvm` and **fails closed** with a diagnostic when they are
  missing. The VMM launcher (config materialization + process lifecycle) now
  exists, but even on a capable host it refuses, because the in-guest agent and
  vsock cell transport are not yet implemented. It never downgrades to a weaker
  boundary.

---

## Explicit answers (hard yes/no)

## 1) Hostile Python code

**Answer: depends on the backend.**

- **`backend="subinterpreter"`: NOT DEFENDED.** The restricted builtins and
  import allow-list are guardrails, not a boundary; adversarial Python can
  bypass them and reach the real interpreter, filesystem, and network from
  inside the supervisor's process. Do not run untrusted code in this mode.

- **`backend="process"`: DEFENDED IN DEPTH (conditional on kernel features).**
  Hostile Python runs in a separate process and is constrained by:
  - process isolation from the supervisor's address space,
  - a seccomp deny-list that kills the process on dangerous syscalls,
  - Landlock filesystem rules from policy (where supported),
  - Landlock TCP-egress rules that deny connect() to any port the policy did
    not allow-list (ABI >= 4; port-granular, a coarse backstop beneath the
    userspace host:port guard),
  - a coarse per-cgroup eBPF/LSM deny-mask (where BPF-LSM is available),
  - broker-mediated privileged operations and per-sandbox resource limits.

  The strength of this answer scales with the kernel features present on the
  host (see the confinement report / `pyisolate doctor --grade`). On a host
  with none of the kernel layers, the process boundary still isolates memory
  but syscall/FS/network policy degrades toward the broker and userspace guards.

**Not covered under either backend:** kernel 0-days, CPU/microarchitectural side
channels, and any path that loads untrusted native code (see §2).

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

1. **Untrusted code runs under `backend="process"`.** The defended answers for
   hostile Python assume the process backend; the sub-interpreter backend is not
   a boundary against it.
2. Trusted host kernel and hardware (no active kernel compromise).
3. The kernel provides the confinement features the deployment relies on
   (seccomp, Landlock, BPF-LSM, cgroup v2). Missing features degrade the
   boundary; hardened rollout mode fails closed rather than degrading silently.
4. Hardened policy configuration (especially denying untrusted native extension
   paths).
5. Supervisor process integrity is maintained.

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

Any semantic change to defended/not-defended status requires:

1. an explicit update to this file,
2. corresponding updates to `SECURITY.md` and user-facing docs,
3. a release note entry calling out the boundary change.

### History

- **2026-07-21** — Wired capability-gated broker mediation into
  `backend="process"`: the guest's `request` cell op is denied unless the named
  capability was granted, and a permitted request crosses the boundary as a
  `BrokerRequest` for supervisor mediation (previously the process backend
  denied all `request` calls). This makes the "broker-mediated privileged
  operations" layer real for the process backend, matching the sub-interpreter
  backend's semantics.
- **2026-07-21** — Added a Landlock TCP-egress layer to `backend="process"`:
  where the kernel's Landlock ABI is >= 4, the policy's TCP allow-list is mapped
  to allowed connect ports and the kernel denies egress to every other port,
  backstopping the userspace host:port guard. Recorded in the confinement report
  (`landlock_net` / `landlock_net_ports`).
- **2026-07-20** — Made the hostile-Python answer backend-conditional. Landed a
  real `backend="process"` boundary: separate-process isolation, a seccomp
  deny-list with `no_new_privs`, Landlock filesystem enforcement from policy,
  and end-to-end wiring of the coarse per-cgroup eBPF/LSM deny-mask. Clarified
  that `backend="subinterpreter"` is not a boundary against hostile Python.
- **2026-04-21** — Initial frozen baseline.
