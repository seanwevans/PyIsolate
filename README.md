# PyIsolate
<img width="256" alt="a sandbox of sandboxes!" src="https://github.com/user-attachments/assets/e5851893-ee13-4466-981e-55d6d08c01db" />

**Current state: prototype.** PyIsolate is a light-weight sub-interpreter sandbox prototype. Kernel eBPF enforcement and CPython no-GIL/free-threaded support are experimental roadmap work, not release guarantees.

## Current release status

PyIsolate `0.0.x` is a prototype for API, policy, broker, observability, and test-matrix development. Do **not** treat this release as a hardened security boundary. The in-repo BPF loader compiles proof-of-concept programs and the default development mode can continue when kernel/BPF tooling is missing. Hardened mode is intentionally fail-closed behind `pyisolate-doctor --mode hardened`.

## Features and roadmap

* **Sub-interpreter sandbox API** — the API surface is available for prototype development and conformance testing. The backend currently executes guests in a dedicated thread, not a CPython sub-interpreter; see [Backend names and what they run](#backend-names-and-what-they-run).
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

## Backend names and what they run

`backend="thread"` runs each guest in a `threading.Thread` of the supervisor
process, `exec`ing guest source against a restricted `__builtins__` mapping. It
is the default.

This backend used to be spelled `backend="subinterpreter"`, which named an
implementation it did not have: `pyisolate/runtime/thread.py` has always used a
thread. That spelling still works and emits a `DeprecationWarning` pointing at
`"thread"`. It is **not** a permanent synonym — the name is reserved for a real
CPython sub-interpreter backend, so pass `"thread"` if you want today's runtime.

The rename changes no security claim. That backend is documented throughout as
an execution cell and *not* a boundary against hostile Python, which is equally
true of a thread and of a real sub-interpreter. What the old name obscured was
the mechanism you should assume when reasoning about it:

| | `thread` | `subinterpreter` |
| --- | --- | --- |
| Address space | shared with supervisor | shared with supervisor |
| `sys.modules` | shared with supervisor | per-interpreter |
| Import allow-list | thread-local bookkeeping | a property of the interpreter |
| Boundary vs hostile Python | none | none |
| GIL | shared | per-interpreter; irrelevant on free-threaded builds |
| Requires | any supported Python | CPython 3.14+ |

`backend="subinterpreter"` runs each guest in its own CPython interpreter via
`concurrent.interpreters`. It needs CPython 3.14+ and **fails closed** below
that rather than quietly handing back a thread, which isolates differently.
It is not the default for that reason.

Neither is a boundary against hostile Python: both share the supervisor's
address space, `ctypes` imports cleanly inside a cell, and any C extension can
reach the whole process. Use `backend="process"` for any guest you do not
trust. What a cell buys over a thread is that one tenant's imports,
monkey-patches and globals cannot be seen or clobbered by another.

Cells are pooled and pre-warmed, because creating one costs 10-57 ms while
dispatching onto a warm one costs 0.8 ms — see
[Performance snapshot](#performance-snapshot). A released cell is *retired*
rather than returned to the pool: an interpreter cannot be reset, so reusing
one across tenants would carry the first tenant's globals into the second.

One operational limit is worth knowing before you deploy it: **a running cell
cannot be reclaimed.** `Interpreter.close()` refuses while the guest is
executing and there is no `kill`, so a cell that overruns its deadline is
*abandoned* — the sandbox raises, the pool stops using that cell, and its
thread stays pinned until the process exits. If you need to survive runaway
guests, run a pool of worker processes and treat the worker as the kill
domain.

---

## The fabric

`backend="fabric"` is the multi-tenant mode: sub-interpreter cells hosted in
**worker processes the supervisor can kill**.

```
 Supervisor
   |
   +-- Worker process   <- the kill domain
   |     +-- cell  cell  cell      (one CellPool, many cells)
   |
   +-- Worker process
         +-- cell  cell
```

It exists because of one limitation the in-process cell backend cannot fix: a
running sub-interpreter **cannot be reclaimed**. `close()` refuses while the
guest executes, there is no `kill`, and an async exception aimed at the thread
does not reach the interpreter running in it. In-process, a runaway guest is
permanent. Putting cells in a worker makes the process the unit of reclaim:

```python
import pyisolate as iso

sb = iso.spawn("report", backend="fabric", tenant="acme", wall_time_ms=500)
sb.exec("while True: pass")
# WallTimeExceeded: cell c1 exceeded 0.5s and did not return. A running
# sub-interpreter cannot be reclaimed, so the worker process hosting it was
# killed; cells sharing that worker were lost with it.
```

Each of the three levels is a different kind of boundary:

| Level | Isolates | Reclaimable |
| --- | --- | --- |
| cell | `sys.modules`, `builtins`, globals | no |
| worker | the kill domain, and where a memory cap applies | **yes — SIGKILL** |
| fabric | decides which worker a tenant lands in | n/a |

**Placement is the blast-radius decision.** With `tenant_isolation=True` (the
default) a worker only ever hosts one tenant's cells, so killing it for a
runaway costs that tenant and nobody else. Turning it off packs tenants
together for density and makes them share a fate. The fabric makes callers
state which they want rather than picking silently.

```python
from pyisolate.runtime.fabric import WorkerPool

pool = WorkerPool(
    max_workers=8,
    cells_per_worker=16,
    tenant_isolation=True,     # one tenant per worker
    worker_mem_bytes=2 << 30,  # RLIMIT_AS per worker
)
pool.prewarm("acme", 2)        # pay the ~160 ms spawn before traffic arrives
```

`worker_mem_bytes` is where a memory limit can actually be enforced:
`sys.getallocatedblocks()` is process-global rather than per-interpreter on
both free-threaded and GIL builds, so there is no per-cell figure to cap.
Worker sizing is the control.

### What it costs

Measured on the same 4-core container as the figures above, free-threaded
CPython 3.14:

| Operation | p50 |
| --- | --- |
| worker spawn (fresh interpreter + pyisolate import + pool) | 160.8 ms |
| first cell for a tenant (spawns its worker) | 190.3 ms |
| further cells in that worker | 29.8 ms |
| `exec` + `recv` round trip | 1.20 ms |

So the kill domain costs about **0.4 ms per round trip** over an in-process
cell (1.20 ms against 0.82 ms) plus one worker spawn per tenant, which
`prewarm` moves off the request path.

### What it is still not

A guest that escapes its cell owns its worker, and a worker is an ordinary
process holding the supervisor's privileges. The fabric is **not** a boundary
against hostile Python. For untrusted code use `backend="process"` — one
confined process per sandbox — or a microVM. What the fabric buys is that
trusted-but-independent tenants cannot wedge each other, and that a tenant
which wedges itself is recoverable.

---

## Canonical execution model

A cell is intentionally limited to seven operations: `exec`, `call`, `post`, `recv`, `log`, `metric`, and `request`.

The API makes the isolation choice explicit: `backend="thread"` means an execution cell, `backend="process"` means a separate OS process boundary, and `backend="microvm"` means a process behind a microVM boundary. The cell contract stays the same across modes, but the security boundary does not: sub-interpreters are not treated as a hard boundary.

See [docs/execution-model.md](docs/execution-model.md). We keep this model small on purpose: production systems are safer when they refuse features outside a single contract.

---

## Security model

**The boundary is the backend.** Pick the backend to match your trust level:

* **`backend="thread"`** (default) - an **execution cell**, not a
  boundary against hostile Python. Today the guest runs in a dedicated
  *thread* of the supervisor's own process, with guest code `exec`'d against a
  restricted `__builtins__` mapping — **not** in a CPython sub-interpreter; the
  backend is named for its intended implementation, which is roadmap work (see
  [Backend names and what they run](#backend-names-and-what-they-run)). Restricted builtins and
  the import allow-list are bypassable guardrails (adversarial Python can walk
  `object.__subclasses__()` to reach the real `os`/`open`). Use it for
  **trusted** code, or for scheduling and organization.
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

All figures are hardware-, kernel-, and build-dependent, and **not** benchmarks
to copy into a comparison. Reproduce them on your own host.

### Shipped backends

From one reference machine *(Ryzen 7950X, Linux 6.9)*. Reproduce with
`python scripts/benchmark.py` (add `--backend process` for the process
boundary):

| Metric            | Value  |
| ----------------- | ------ |
| Spawn latency     | 0.7 ms |
| Round-trip (1 kB) | 70 us  |

These are numbers for the **thread** backend -- the runtime that
`backend="subinterpreter"` selects today (see
[Sub-interpreter status](#sub-interpreter-status)). They are not what a real
CPython sub-interpreter costs, and the roadmap item that lands real
sub-interpreters will make them substantially worse; the next section measures
what it will cost.

### What a real sub-interpreter costs

`python scripts/cell_cost.py` measures the CPython primitives the planned
sub-interpreter backend would be built on, so the roadmap can be argued from
numbers taken on a real machine rather than from the assumption that a
sub-interpreter is cheap. From one run on free-threaded CPython 3.14 (4-core
container, `--iterations 30`):

| Import surface in the cell                | create+exec (p50) | close (p50) | RSS/cell |
| ----------------------------------------- | ----------------- | ----------- | -------- |
| bare (`x = 1`)                            | 10.9 ms           | 3.9 ms      | 3.5 MiB  |
| `json, re, dataclasses`                   | 29.2 ms           | 7.8 ms      | 7.7 MiB  |
| `+ email, http.client, logging, argparse` | 56.8 ms           | 13.3 ms     | 13.3 MiB |

| Reference point                         | p50     |
| --------------------------------------- | ------- |
| dispatch onto an already-warm pool cell | 0.82 ms |
| `fork()` of a warm parent               | 1.62 ms |

Three things follow, and they shape the roadmap:

* **Creating a cell is not cheap.** A sub-interpreter re-imports every module it
  uses with no copy-on-write sharing, so the import surface -- not the
  interpreter object -- dominates. A `fork()`, which *is* a real boundary, costs
  less than the cheapest possible cell.
* **Cells are only cheap when pooled.** 0.82 ms to dispatch onto a warm
  interpreter is the number worth designing around, which means a pool of cells
  with pre-warmed import surfaces, not an interpreter per request.
* **Parallelism comes from the build, not from the interpreters.** On the same
  4-core box four cells scaled 3.9x -- but four *plain threads* on that
  free-threaded build scaled 3.3x too. On a GIL build (3.13) those threads
  scaled 0.96x while cells scaled 3.3x. So sub-interpreters buy parallelism on a
  GIL build, and buy a private `sys.modules` and a private set of globals per
  tenant on a free-threaded one.

The encrypted-throughput and baseline-RSS rows previously quoted here are not
produced by either script, and have been dropped rather than left as figures
nobody can reproduce.


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
