# ROADMAP

PyIsolate is a **prototype**. This document tracks what already exists, what is
actively being built, and where the project is headed. The security boundary is
backend-conditional — see [docs/threat-model.md](docs/threat-model.md) for the
normative statement.

## Delivered

- **Backends** — `backend="subinterpreter"` (execution cell) and
  `backend="process"` (the boundary mode): a real separate-process boundary with
  `no_new_privs` + a seccomp deny-list, Landlock filesystem rules, Landlock
  TCP-egress rules (ABI ≥ 4), a coarse per-cgroup eBPF/LSM deny-mask, and
  `rlimit` caps, recorded in a per-sandbox confinement report.
- **Broker transport** — X25519 (optional Kyber-768 hybrid) → ChaCha20-Poly1305
  authenticated channel with per-direction replay counters; capability-gated
  `request` cell op in both backends.
- **Policy** — YAML policy model + compiler, token-gated hot-reload, and remote
  refresh over bounded HTTP(S).
- **No-GIL axis** — free-threaded build / GIL / native-extension classification
  with a release gate and CI coverage.
- **Observability** — Prometheus metrics, structured logging, `pyisolate doctor`
  provenance, and a 10-point `--grade` conformance score.
- **Packaging** — PyPI metadata + a Trusted-Publishing release workflow (tooling
  in place; no release cut yet).
- **microVM scaffolding** — VMM/KVM capability detection, fail-closed admission,
  a Firecracker machine-config builder, and a VMM launcher (process lifecycle).
- **Also shipped** — encrypted checkpointing, checkpoint migration to a peer,
  NUMA-aware scheduling, a CLI, a policy editor, and pre-commit + CI.

## Now / next

- **Broker request execution** — the `request` op currently surfaces a
  `BrokerRequest` to the host but nothing executes it or returns a result. Add a
  request/response round-trip and a pluggable, capability-scoped handler so the
  broker actually mediates privileged operations.
- **Process-backend quota enforcement** — attach process-backed sandboxes to
  cgroups and cover them with the `ResourceWatchdog` (today they get `rlimit`
  only and are not watched), so the boundary mode gets the CPU/memory quota
  enforcement the threat model credits it with.
- **microVM guest agent + vsock transport** — the launcher can boot a VMM; the
  remaining work is the in-guest agent and carrying the cell protocol over
  vsock, which is what makes `backend="microvm"` a usable, working boundary.
- **Cut `v0.0.1` to PyPI** — using the existing release workflow, once a Trusted
  Publisher and `pypi` environment are configured.

## Security hardening

- **Richer eBPF/LSM enforcement** — move beyond the coarse per-cgroup deny-mask
  toward per-path / per-destination allow-lists in the LSM layer.
- **Landlock network `bind` restriction** — complement the existing egress
  (`connect`) rules.
- **Input validation & constant-time error paths** on broker messages.
- **Hardware-assisted checks** — evaluate Intel CET, ARM pointer authentication,
  and MTE where supported.
- **Supply chain** — reproducible builds, artifact signing, and eBPF-bytecode
  pinning (currently roadmap, not guaranteed).

## Extended functionality

- **WASM build target** to run a sandbox inside browsers.
- **gRPC control-plane plugin** for managing remote sandboxes.
- **Language bindings** for Rust and Go.
- **Kubernetes operator** — currently minimal (`pyisolate[operator]`); grow it
  into a real reconciler with a documented CRD.

## Long-term vision

- **Distributed supervisor** scheduling sandboxes across hosts.
- **Live migration** of running sandboxes between hosts.
- **Policy plugin ecosystem** for community-contributed guards and metrics.
- **Comprehensive dashboards** with Grafana and alerting hooks.
