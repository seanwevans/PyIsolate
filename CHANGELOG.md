# Changelog

All notable changes to PyIsolate are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). PyIsolate is a
prototype in the `0.0.x` series and does not yet make Semantic Versioning
guarantees; **no release should be treated as a hardened security boundary**.

## [Unreleased]

### Added
- `backend="subinterpreter"`: real CPython sub-interpreter cells on 3.14+, via
  `concurrent.interpreters`, with a pre-warmed `CellPool`. Each guest gets its
  own `sys.modules` and its own `builtins`, so the import allow-list is a
  property of the interpreter rather than thread-local state. Still an
  execution cell, not a boundary against hostile Python. Fails closed below
  3.14 rather than degrading to the thread backend.

- `backend="process"` boundary mode: a real separate-process boundary confined
  by `no_new_privs` + a seccomp deny-list, Landlock filesystem rules, Landlock
  TCP-egress rules (Landlock ABI ≥ 4), a coarse per-cgroup eBPF/LSM deny-mask,
  and `rlimit` caps, recorded in a per-sandbox confinement report.
- Capability-gated broker `request` mediation in the process backend (surfaces a
  `BrokerRequest` to the supervisor; an ungranted capability is denied).
- microVM backend scaffolding: VMM/KVM capability detection, fail-closed
  admission, a Firecracker machine-config builder, and a VMM launcher.
- No-GIL readiness axis tests and a free-threaded (`3.13t`) CI gate.
- PyPI packaging metadata and a Trusted-Publishing release workflow.
- `pyisolate doctor --grade` components for Landlock network egress and microVM
  readiness (now a 10-point conformance score).
- `scripts/benchmark.py` for reproducible spawn/round-trip measurements.
- `pyisolate[operator]` optional-dependency group for the Kubernetes operator.

### Changed
- `backend="subinterpreter"` is renamed to `backend="thread"`, which is what it
  has always run, and the `subinterpreter` name now selects the real
  sub-interpreter backend. `DEPRECATED_BACKEND_ALIASES` is exported alongside
  `SUPPORTED_BACKENDS` and is currently empty.
- Threat model and `SECURITY.md` reconciled with the real, backend-conditional
  boundary (the sub-interpreter backend is an execution cell, not a boundary
  against hostile Python).

### Known gaps
- The broker `request` op is surfaced but not yet executed end-to-end.
- A running sub-interpreter cell cannot be reclaimed: one that overruns its
  wall-time deadline is abandoned, and its thread stays pinned until the
  process exits. Cells enforce a wall-time deadline and no other quota;
  `sys.getallocatedblocks()` is process-global, so per-cell memory
  accounting needs a worker-process layer that does not exist yet.
- Process-backed sandboxes are not attached to cgroups or watched by the
  resource watchdog (they get `rlimit` only).
- `backend="microvm"` fails closed: the guest agent and vsock cell transport are
  not implemented yet.
