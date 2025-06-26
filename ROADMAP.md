# ROADMAP

This document outlines planned milestones for PyIsolate. Items are a mix of
implemented features, work implied by the existing design, and ideas to improve
the project.

## 1 Short‑term goals

- **Complete agent implementations** — flesh out `BPFManager`, `CryptoBroker`,
  and `ResourceWatchdog` so that they enforce policies rather than acting as
  stubs.
- **Policy hot‑reloading** — wire up `policy.refresh()` to update BPF maps
  without restarting sandboxes.
- **Metrics exporter** — collect per‑sandbox counters and expose Prometheus
  gauges as sketched in `observability/metrics.py`.

## 2 Security hardening

- **Landlock fallback** for systems without eBPF privileges.
- **Post‑quantum handshake** using Kyber‑736 / Dilithium hybrids.
- **Input validation** on broker messages and strict constant‑time error paths.
- **Hardware-assisted checks** — evaluate Intel CET, ARM pointer authentication,
  and MTE for platforms that support them.

## 3 Developer experience

- **Command‑line interface** for spawning and monitoring sandboxes.
- **Pre‑commit hooks** and CI on all supported platforms.
- **Package to PyPI** so users can install with `pip`.

## 4 Extended functionality

- **WASM build target** to run the sandbox inside browsers.
- **gRPC control‑plane plugin** for managing remote sandboxes.
- **Language bindings** for Rust and Go to drive PyIsolate from other projects.
- **Remote policy enforcement** over HTTP.
- **Encrypted checkpointing** for sandbox migration.

## 5 Long‑term vision

- **Distributed supervisor** that schedules sandboxes across multiple hosts.
- **Live migration** of running sandboxes between hosts.
- **Policy plugin ecosystem** allowing community‑contributed guards and metrics.
- **Comprehensive dashboards** with Grafana and alerting hooks.

