# PyIsolate

[![CI](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/seanwevans/pyisolate/actions/workflows/ci.yml)
[![Coverage Status](https://raw.githubusercontent.com/seanwevans/pyisolate/main/docs/coverage.svg)](https://raw.githubusercontent.com/seanwevans/pyisolate/main/docs/coverage.svg)
[![Pylint Score](https://raw.githubusercontent.com/seanwevans/pyisolate/main/docs/pylint.svg)](https://raw.githubusercontent.com/seanwevans/pyisolate/main/docs/pylint.svg)

**Light‑weight, eBPF‑hardened sub‑interpreter sandbox for CPython 3.13 (no‑GIL)**

> Docker‑class isolation, thread‑level granularity.

## Features

* **True parallelism** — built on CPython 3.13 with the `--disable-gil` build.
* **Kernel‑enforced security** — eBPF‑LSM & cgroup hooks gate filesystem, network, and high‑risk syscalls.
* **Deterministic quotas** — per‑interpreter arenas cap RAM; perf‑event BPF guards CPU & bandwidth.
* **io_uring async I/O** — broker uses Linux io_uring for non-blocking operations.
* **Token‑gated policy reload** — update YAML policies in micro‑seconds with authentication.
* **Authenticated broker** — X25519 (optionally Kyber‑768) + ChaCha20‑Poly1305 secure control channel with replay counters.
* **Hot‑reload policy** — update YAML policies in micro‑seconds without restarting guests.
* **eBPF‑verified contracts** — runtime assertions compiled into BPF for extra safety.
* **Observability** — Prometheus metrics & eBPF perf‑events for every sandbox.
* **Stack canaries & CFI** — sub‑interpreter compiled with `-fstack-protector-strong` and `-fsanitize=cfi`.
* **NUMA‑aware scheduling** — bind sandboxes to the CPUs of a chosen node on multi‑socket hosts.
* **Remote policy enforcement** — fetch and apply YAML over HTTP.
* **Encrypted checkpointing** — save sandbox state with ChaCha20‑Poly1305.
* **Migration** — transfer checkpoints to a peer host.

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

code = """
from math import sqrt
post(sqrt(2))
"""

with iso.spawn("demo", policy="stdlib.readonly") as sandbox:
    sandbox.exec(code)
    print("Result:", sandbox.recv())   # 1.4142135623730951
```


### Policy editor

Run a minimal GUI to tweak and hot‑reload YAML policies:

```bash
python -m pyisolate.editor policy/example.yml
```
The debug box lets you test file paths or addresses against the live policy.

### Policy templates

Ready-made YAML policies live in the `policy/` directory.  The following
templates cover common scenarios:

* **`ml.yml`** – baseline for machine learning workloads with outbound HTTPS
  access and generous CPU/memory limits.
* **`web_scraper.yml`** – permits HTTP/HTTPS to the public internet while
  restricting filesystem access to `/tmp`.

Use `pyisolate.policy.refresh()` to hot‑load any of these files at runtime.


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
 │   ↑         ↑              ↑         │
 │   │channel  │              │         │
 └───┴─────────┴──────────────┴─────────┘
       eBPF cgroups & LSM hooks per thread
```

---

## Security model

* **Process boundary** – single process; sub‑interpreter ≙ trust boundary.
* **Kernel boundary** – every sandbox thread enters its own cgroup; CO‑RE eBPF programs enforce FS/net/syscall policy.
* **Broker** – sole path to privileged syscalls, sealed with AEAD and strict replay protection.
* **Verified eBPF modules** – bytecode is disassembled with `llvm-objdump -d` and must succeed `bpftool prog load` so the kernel verifier approves it before any sandbox runs.

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
* [x] Add Kyber‑768 / Dilithium PQ hybrids
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

## Kubernetes deployment

A `Dockerfile` and experimental operator are included. See [docs/kubernetes.md](docs/kubernetes.md) for details.

---

## License

MIT – see `LICENSE`.

## Acknowledgements

Inspired by PyO3, Tetragon, libsodium, and decades of sandbox research.
