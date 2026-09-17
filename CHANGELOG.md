# Changelog

All notable changes to PyIsolate are recorded here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). PyIsolate is a
prototype in the `0.0.x` series and does not yet make Semantic Versioning
guarantees; **no release should be treated as a hardened security boundary**.

## [Unreleased]

### Added
- `backend="fabric"`: the multi-tenant mode. Sub-interpreter cells hosted in
  worker processes the supervisor can kill, which is the only reclaim that
  works on a running cell. A deadline that expires kills the worker and the
  tenant keeps running on a fresh one; other tenants are untouched. Includes
  tenant-aware placement (`tenant_isolation=True` by default, so a kill costs
  one tenant), per-worker `RLIMIT_AS` caps, `prewarm` to move the ~160 ms
  worker spawn off the request path, worker recycling with counters, and
  `Supervisor.fabric_report()` for placement visibility. Needs CPython 3.14+
  and fails closed below it.

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
- CI covers CPython 3.14: the unit matrix gains `3.14`, and a new
  `sub-interpreter cells / py3.14t` job runs the sub-interpreter backend on a
  free-threaded build. That job asserts the interpreter really is a
  free-threaded 3.14 before running anything, because every sub-interpreter
  test skips itself when the build cannot run it -- correct for the 3.11-3.13
  matrix, but it would otherwise let the job report green having tested
  nothing.
- `backend="subinterpreter"` is renamed to `backend="thread"`, which is what it
  has always run, and the `subinterpreter` name now selects the real
  sub-interpreter backend. `DEPRECATED_BACKEND_ALIASES` is exported alongside
  `SUPPORTED_BACKENDS` and is currently empty.
- Threat model and `SECURITY.md` reconciled with the real, backend-conditional
  boundary (the sub-interpreter backend is an execution cell, not a boundary
  against hostile Python).

### Known gaps
- The broker `request` op is surfaced but not yet executed end-to-end.
- The eBPF programs compile to loadable objects and are covered by ELF-level
  tests, but load/attach against a live verifier is still only exercised by
  the root-gated `PYISOLATE_LIVE_BPF_TESTS=1` tests, not by CI.
- In `backend="subinterpreter"` a running cell still cannot be reclaimed: one
  that overruns is abandoned and its thread stays pinned until the process
  exits. Use `backend="fabric"`, where the worker is the kill domain.
- A fabric worker is an ordinary process with the supervisor's privileges: the
  fabric bounds faults, not hostile Python. Kernel confinement of workers is
  not implemented.
- The broker `request` op is surfaced by the fabric but, as with the other
  backends, nothing executes it.
- Memory is capped per worker (`RLIMIT_AS`), not per cell:
  `sys.getallocatedblocks()` is process-global on both free-threaded and GIL
  builds, so there is no per-cell figure to limit.
- Process-backed sandboxes are not attached to cgroups or watched by the
  resource watchdog (they get `rlimit` only).
- `backend="microvm"` fails closed: the guest agent and vsock cell transport are
  not implemented yet.
