# Changelog

All notable changes to PyIsolate are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). PyIsolate is a
prototype in the `0.0.x` series and does not yet make Semantic Versioning
guarantees; **no release should be treated as a hardened security boundary**.

## [Unreleased]

### Added
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

### Fixed
- eBPF programs are now built in a shape the kernel can load. They were
  compiled without `-g`, so the objects carried no BTF and libbpf could not
  parse their BTF-defined `.maps` sections; every `lsm/*` handler declared
  typed parameters without libbpf's `BPF_PROG` wrapper, so it read `r2` --
  a register an LSM program's caller never sets -- which the verifier rejects;
  and `resource_guard.bpf.c` declared two `struct { int dummy; }` placeholders
  in `.maps`, which are not map definitions libbpf can parse. Handlers now
  unpack the LSM context array by index, `socket_connect` copies `sa_family`
  with `bpf_probe_read_kernel` rather than dereferencing an untyped kernel
  pointer, and the placeholder maps and their dead no-op programs are gone.

### Changed
- Threat model and `SECURITY.md` reconciled with the real, backend-conditional
  boundary (the sub-interpreter backend is an execution cell, not a boundary
  against hostile Python).

### Known gaps
- The broker `request` op is surfaced but not yet executed end-to-end.
- The eBPF programs compile to loadable objects and are covered by ELF-level
  tests, but load/attach against a live verifier is still only exercised by
  the root-gated `PYISOLATE_LIVE_BPF_TESTS=1` tests, not by CI.
- Process-backed sandboxes are not attached to cgroups or watched by the
  resource watchdog (they get `rlimit` only).
- `backend="microvm"` fails closed: the guest agent and vsock cell transport are
  not implemented yet.
