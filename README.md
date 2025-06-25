# PyIsolate

[![Black](https://github.com/your/pyisolate/actions/workflows/ci.yml/badge.svg?branch=main&label=black)](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml)
[![Isort](https://github.com/your/pyisolate/actions/workflows/ci.yml/badge.svg?branch=main&label=isort)](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml)
[![Flake8](https://github.com/your/pyisolate/actions/workflows/ci.yml/badge.svg?branch=main&label=flake8)](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml)
[![Pylint](https://github.com/your/pyisolate/actions/workflows/ci.yml/badge.svg?branch=main&label=pylint)](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml)
[![Coverage](docs/coverage.svg)](docs/coverage.svg)

**Light‑weight, eBPF‑hardened sub‑interpreter sandbox for CPython 3.13 (no‑GIL)**

> Docker‑class isolation, thread‑level granularity.

## Features

* **True parallelism** — built on CPython 3.13 with the `--disable-gil` build.
* **Kernel‑enforced security** — eBPF‑LSM & cgroup hooks gate filesystem, network, and high‑risk syscalls.
* **Deterministic quotas** — per‑interpreter arenas cap RAM; perf‑event BPF guards CPU & bandwidth.
* **Authenticated broker** — X25519 + ChaCha20‑Poly1305 secure control channel with replay counters.
* **Hot‑reload policy** — update YAML policies in micro‑seconds without restarting guests.
* **Observability** — Prometheus metrics & eBPF perf‑events for every sandbox.

---

## Quick start

```bash
git clone https://github.com/seanwevans/pyisolate.git
cd pyisolate
python -m pip install -e .[dev]  # install package for development and tooling
pytest -q          # run the test‑suite
python examples/echo.py
```

### Hello World

```python
import pyisolate as iso

sandbox = iso.spawn("demo", policy="stdlib.readonly")

code = """
from math import sqrt
post(sqrt(2))
"""

sandbox.exec(code)
print("Result:", sandbox.recv())   # 1.4142135623730951
sandbox.close()
```

---

## Architecture

```
 ┌──────── Supervisor (root) ───────────┐
 │  • eBPF loader & maps                │
 │  • Broker (AEAD, counters)           │
 │  • Policy hot‑reloader               │
 │  • Metrics exporter (Prometheus)     │
 ├──────────────────────────────────────┤
 │ Thread A   Thread B   …  Thread N    │
 │ ╭─────╮   ╭─────╮        ╭─────╮     │
 │ │ SB1 │   │ SB2 │  …     │ SBN │     │
 │ ╰─────╯   ╰─────╯        ╰─────╯     │
 │   ↑         ↑            ↑           │
 │   │channel  │            │           │
 └───│─────────│────────────│───────────┘
       eBPF cgroups & LSM hooks per thread
```

---

## Security model

* **Process boundary** – single process; sub‑interpreter ≙ trust boundary.
* **Kernel boundary** – every sandbox thread enters its own cgroup; CO‑RE eBPF programs enforce FS/net/syscall policy.
* **Broker** – sole path to privileged syscalls, sealed with AEAD and strict replay protection.

See **SECURITY.md** for a full threat‑model walkthrough.

---

## Performance snapshot *(Ryzen 7950X, Linux 6.9)*

| Metric                  | Value   |
| ----------------------- | ------- |
| Spawn latency           | 0.7 ms  |
| Round‑trip (1 kB)       | 70 µs   |
| Max encrypted msgs/core | 1.9 M/s |
| Baseline RSS            | 0.5 MiB |

---

## Roadmap

* [ ] Land Landlock fallback for unprivileged kernels
* [ ] Add Kyber‑768 / Dilithium PQ hybrids
* [ ] WASM build target for browser sandboxes
* [ ] gRPC control‑plane plugin

---

## Contributing

1. Fork & create a feature branch.
2. Enable `pre‑commit` hooks (`pre‑commit install`).
3. Run `pre-commit run --all-files` and ensure CI passes.
4. Submit a PR with docs & tests.

### Community

* Discord: **#pyisolate**
* Matrix: `#pyisolate:matrix.org`

---

## License

MIT – see `LICENSE`.

## Acknowledgements

Inspired by PyO3, Tetragon, libsodium, and decades of sandbox research.
