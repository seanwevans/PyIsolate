# PyIsolate
<img width="256" alt="a sandbox of sandboxes!" src="https://github.com/user-attachments/assets/e5851893-ee13-4466-981e-55d6d08c01db" />

**Current state: prototype.** PyIsolate is a light-weight sub-interpreter sandbox prototype. Kernel eBPF enforcement and CPython no-GIL/free-threaded support are experimental roadmap work, not release guarantees.

## Current release status

PyIsolate `0.0.x` is a prototype for API, policy, broker, observability, and test-matrix development. Do **not** treat this release as a hardened security boundary. The in-repo BPF loader compiles proof-of-concept programs and the default development mode can continue when kernel/BPF tooling is missing. Hardened mode is intentionally fail-closed behind `pyisolate-doctor --mode hardened`.

## Features and roadmap

* **Sub-interpreter sandbox API** — available for prototype development and conformance testing.
* **Import allow-listing and user-space quotas** — available as prototype guardrails; not a complete adversarial security boundary.
* **No-GIL/free-threaded CPython support** — experimental roadmap target for CPython 3.13+ `--disable-gil` builds.
* **Kernel enforcement** — experimental roadmap target; eBPF-LSM, cgroup, and verifier-backed policy enforcement are not guaranteed by the current release.
* **Deterministic quotas** — roadmap: per-interpreter arenas plus perf-event BPF guards for CPU and bandwidth.
* **Kernel-level accounting** — experimental: `resource_guard.bpf.c` is a proof-of-concept ring-buffer source.
* **io_uring async I/O** — broker uses Linux io_uring for non-blocking operations.
* **Token‑gated policy reload** — update YAML policies in micro‑seconds with authentication.
* **Authenticated broker** — X25519 (optionally Kyber‑768) + ChaCha20‑Poly1305 secure control channel with replay counters.
* **Hot‑reload policy** — update YAML policies in micro‑seconds without restarting guests.
* **eBPF‑verified contracts** — roadmap: runtime assertions compiled into BPF for extra safety.
* **Observability** — Prometheus metrics are available; eBPF perf-event coverage is experimental.
* **Capability imports** — restrict module access per sandbox via `allowed_imports`.
* **Restricted subset** — optional interpreter with move-only ownership semantics.
* **Stack canaries & CFI** — sub‑interpreter compiled with `-fstack-protector-strong` and `-fsanitize=cfi`.
* **NUMA‑aware scheduling** — bind sandboxes to the CPUs of a chosen node on multi‑socket hosts.
* **Remote policy refresh** — fetch and apply YAML over HTTP to prototype policy maps.
* **Encrypted checkpointing** — save sandbox state with ChaCha20‑Poly1305.
* **Migration** — transfer checkpoints to a peer host.

---

## Quick start

```bash
git clone https://github.com/seanwevans/pyisolate.git
cd pyisolate
python -m pip install -e .[dev]  # install package for development and tooling
# Optional: enable Kyber-768 hybrid handshakes with the pqcrypto extra
# python -m pip install -e .[dev,pqcrypto]
pytest -q          # run the test‑suite
python examples/echo.py
pyisolate-doctor                 # capture provenance + feature report
pyisolate-doctor --mode hardened # fail closed on unsupported no-GIL/kernel/BPF config
```

### CI test matrix

The CI pipeline runs a security/stability matrix beyond unit tests:

* adversarial and import-escape scenarios
* runaway CPU and memory exhaustion limits
* file/network policy-bypass attempts
* high-concurrency race checks (including free-threaded `3.13t`)
* soak runs with thousands of spawn/kill cycles on nightly schedule
* crash-injection recovery checks
* cross-kernel smoke runs on Ubuntu 22.04 and 24.04

Run the hardening suite locally with:

```bash
pytest -q tests/test_matrix_hardening.py
```

### Packaging and reproducibility

PyIsolate includes a `pyisolate-doctor` command for installation diagnostics and
release provenance tracking (Python build hash, no-GIL status, kernel features,
BPF toolchain availability, and deterministic-wheel policy flags). In `--mode hardened`, unsupported Python, kernel, or BPF configurations are reported as hard failures with a non-zero exit code. See [docs/packaging-reproducibility.md](docs/packaging-reproducibility.md).

### Structured logging

Enable JSON-formatted logs for easier parsing:

```python
from pyisolate.logging import setup_structured_logging

setup_structured_logging()
```

### Rollout modes

Choose a supervisor rollout profile based on where you are deploying:

```python
import pyisolate as iso

# production default: fail closed if the BPF toolchain, verifier, load, or attach fails
hardened = iso.Supervisor(rollout_mode="hardened")

# explicitly acknowledge weaker enforcement for local iteration
dev = iso.Supervisor(rollout_mode="dev")

# explicitly acknowledge reduced enforcement for ecosystem validation
compat = iso.Supervisor(rollout_mode="compatibility")
```

* `hardened`: documented production default with kernel LSM/cgroup enforcement; any eBPF compile/load/attach failure raises.
* `dev`: caller-acknowledged local development mode; tooling failures are logged and kernel enforcement can be absent.
* `compatibility`: caller-acknowledged reduced enforcement to maximize third-party compatibility; strict filters are skipped.

### Hello World

```python
import pyisolate as iso

code = """
from math import sqrt
post(sqrt(2))
"""

with iso.spawn("demo", allowed_imports=["math"]) as sandbox:
    sandbox.exec(code)
    print("Result:", sandbox.recv())   # 1.4142135623730951
```


Higher‑level helpers can automatically sandbox functions and build simple
pipelines. Policy names in these examples are labels for prototype routing until
the hardened gate passes; do not rely on them for kernel enforcement:

```python
@iso.sandbox(policy="ml-inference", timeout="30s")
def run_model(data):
    ...

pipeline = iso.Pipeline()
pipeline.add_stage("extract", policy="readonly-fs")
pipeline.add_stage("transform", policy="compute-only")
pipeline.add_stage("load", policy="write-db")
```


### Restricting imports

```python
sb = iso.spawn("safe", allowed_imports=["math"])
sb.exec("from math import sqrt; post(sqrt(9))")
print(sb.recv())  # 3.0
```

For CPython 3.13 `--disable-gil` deployments, review the extension and package compatibility guidance in [docs/compatibility-matrix.md](docs/compatibility-matrix.md) before expanding `allowed_imports`.


### Host conformance suite

Run the host conformance suite to measure how close the current machine is to
PyIsolate roadmap guarantees (Python build, kernel capabilities, BPF readiness,
cgroup behavior, policy enforcement, and timeout/kill behavior):

```bash
python -m pyisolate.conformance
python -m pyisolate.conformance --json
python -m pyisolate.conformance --grade
pyisolate-doctor --grade
```

The `--grade` output replaces a vague secure/insecure claim with a 10-point
score over the guarantees that are actually active on the host: free-threading,
eBPF-LSM, cgroup v2, Landlock fallback, Landlock network egress, no-GIL extension
safety, broker crypto, quota enforcement, crash isolation, and microVM readiness.
Use it in CI or admission checks to attach evidence to each guarantee rather than
relying on a single pass/fail bit.

### Policy editor

Run a minimal GUI to tweak and hot‑reload YAML policies:

```bash
python -m pyisolate.editor policy/example.yml
```
The debug box lets you test file paths or addresses against the live policy.
When you click **Reload**, the editor will ask for the policy token unless one
was supplied via ``PolicyEditor(token="…")``.

### Policy templates

Ready-made YAML policies live in the `policy/` directory.  The following
templates cover common scenarios:

* **`ml.yml`** – baseline for machine learning workloads with outbound HTTPS
  access and generous CPU/memory limits.
* **`web_scraper.yml`** – permits HTTP/HTTPS to the public internet while
  restricting filesystem access to `/tmp`.

Use `pyisolate.policy.refresh("policy/<name>.yml", token="secret")` to hot‑load any of these files at runtime.


---

## Architecture

```
 ┌──────── Supervisor (root) ───────────┐
 │  • experimental eBPF loader & maps   │
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
       roadmap: eBPF cgroups & LSM hooks per thread
```

---

## Canonical execution model

A cell is intentionally limited to seven operations: `exec`, `call`, `post`, `recv`, `log`, `metric`, and `request`.

The API makes the isolation choice explicit: `backend="subinterpreter"` means an execution cell, `backend="process"` means a separate OS process boundary, and `backend="microvm"` means a process behind a microVM boundary. The cell contract stays the same across modes, but the security boundary does not: sub-interpreters are not treated as a hard boundary.

See [docs/execution-model.md](docs/execution-model.md). We keep this model small on purpose: production systems are safer when they refuse features outside a single contract.

---

## Security model

**The boundary is the backend.** Pick the backend to match your trust level:

* **`backend="subinterpreter"`** (default) - an **execution cell**, not a
  boundary against hostile Python. The guest runs in a sub-interpreter in the
  supervisor's own process; restricted builtins and the import allow-list are
  bypassable guardrails (adversarial Python can walk `object.__subclasses__()`
  to reach the real `os`/`open`). Use it for **trusted** code, or for scheduling
  and organization.
* **`backend="process"`** - the **boundary mode**. The guest runs in a separate
  OS process, confined in depth by the kernel before any guest code runs:
  * `PR_SET_NO_NEW_PRIVS` + a seccomp deny-list that kills the process on
    dangerous syscalls (`execve`, `ptrace`, mount/namespace ops, `bpf`, module
    load, `process_vm_*`, ...) - x86-64 Linux;
  * **Landlock** filesystem rules from policy, plus **Landlock TCP-egress**
    rules (ABI ≥ 4) that deny `connect()` to any port outside the policy's
    allow-list, where the kernel supports it;
  * a coarse per-cgroup **eBPF/LSM** `deny_mask`, where BPF-LSM is available;
  * `rlimit` and cgroup resource caps.
  Each kernel layer is best-effort and recorded in the sandbox's confinement
  report; hardened rollout mode fails closed when a required layer is missing.
* **`backend="microvm"`** - the reserved hardware-VM boundary. The supervisor
  probes the host for a supported VMM (Firecracker, Cloud Hypervisor, QEMU) and
  an accessible `/dev/kvm`, and **fails closed** with a diagnostic naming what is
  missing. The VMM launcher (config materialization + process lifecycle) now
  exists, but even on a capable host the backend still refuses, because the
  in-guest agent and vsock cell transport are not yet implemented. It never
  degrades to a weaker boundary.
* **Broker** - sole path to privileged syscalls, sealed with AEAD (X25519 to
  ChaCha20-Poly1305) and strict per-direction replay counters.
* **Fallback hardening** - even the process backend is defense-in-depth, not a
  hardware-VM boundary. For hostile multi-tenant workloads, run one sandbox per
  process inside a container or microVM.

See **[SECURITY.md](SECURITY.md)** and the normative
**[threat model](docs/threat-model.md)** for the full, backend-conditional
boundary statement.

---

## Performance snapshot

These are indicative figures from one reference machine *(Ryzen 7950X, Linux
6.9, sub-interpreter backend)* — hardware-, kernel-, and build-dependent, and
**not** a benchmark to copy into a comparison. Reproduce them on your own host
with `python scripts/benchmark.py` (add `--backend process` for the process
boundary); the encrypted-throughput and RSS rows are not yet covered by it.

| Metric                  | Value   |
| ----------------------- | ------- |
| Spawn latency           | 0.7 ms  |
| Round‑trip (1 kB)       | 70 µs   |
| Max encrypted msgs/core | 1.9 M/s |
| Baseline RSS            | 0.5 MiB |

---

## Kubernetes deployment

A `Dockerfile` and experimental operator are included. See [docs/kubernetes.md](docs/kubernetes.md) for details.

---

## Roadmap

* [ ] Harden kernel-backed FS/net/syscall policy enforcement
* [ ] Support and test CPython 3.13+ no-GIL/free-threaded deployments
* [ ] Land Landlock fallback for unprivileged kernels
* [x] Add Kyber‑768 / Dilithium PQ hybrids
* [ ] WASM build target for browser sandboxes
* [ ] gRPC control‑plane plugin

---

## Contributing

1. Fork & create a feature branch.
2. Enable `pre‑commit` hooks (`pre‑commit install`). Black handles formatting and isort handles import ordering, alongside Flake8, Pylint, and Mypy for linting.
3. Run `pre-commit run --all-files` and ensure CI passes.
4. Submit a PR with docs & tests.

---

## License

MIT – see `LICENSE`.

## Acknowledgements

Inspired by PyO3, Tetragon and libsodium.

## No-GIL readiness is a release axis

PyIsolate distinguishes **parallel cells** from **scheduled compartments**. A
host may claim parallel-cell semantics only when the interpreter is a
`--disable-gil` build, the process GIL is not enabled, and loaded native
extensions have explicit no-GIL safety declarations. Otherwise PyIsolate treats
work as scheduled compartments: isolated and policy-controlled, but not a hard
parallel execution guarantee.

Use the doctor subcommands to make this visible in CI and fleet diagnostics:

```bash
pyisolate doctor gil
pyisolate doctor gil --json
pyisolate doctor extensions
pyisolate doctor extensions --json
```

The legacy `pyisolate-doctor` command still prints the full provenance report,
including the `no_gil.axis.mode` field. On free-threaded builds, PyIsolate emits
a `RuntimeWarning` when native extensions are already imported but not declared
safe through `PYISOLATE_NOGIL_SAFE_MODULES`. Only set that environment variable
after auditing upstream support for subinterpreters and CPython no-GIL/free
threading.
