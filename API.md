# API.md — Public Python Interface (prototype v0.1)

**Current state:** PyIsolate is a prototype. Kernel eBPF enforcement and CPython 3.13 no-GIL/free-threaded support are experimental roadmap items. Development and compatibility modes must not be described as hardened isolation because they can run without full kernel enforcement.

```python
import pyisolate as psi
```

## 1  Spawning & lifecycle

### Canonical cell execution model

PyIsolate supports exactly seven cell operations: `exec`, `call`, `post`, `recv`, `log`, `metric`, and `request`.

Isolation mode is explicit in the public API. Use `backend="subinterpreter"` for the execution-cell backend, `backend="process"` for one sandbox per OS process, and `backend="microvm"` for a process placed behind a microVM boundary. The cell contract is the same in every mode, but only the process and microVM modes are intended to represent hard blast-radius boundaries.

The canonical contract lives in [docs/execution-model.md](docs/execution-model.md). Keep this surface small; production systems win by refusing extra features.

| Call | Description |
|------|-------------|
| `psi.spawn(name:str, policy:str|dict=None, allowed_imports:list[str]|None=None) → Sandbox` | Create sandbox thread and return a handle with module whitelist. Policy attachment is prototype behavior unless hardened diagnostics pass. |
| `psi.Supervisor(warm_pool:int=0, rollout_mode:str="dev")` | Build a prototype supervisor with explicit rollout posture (`dev`, experimental fail-closed `hardened`, or non-enforcing `compatibility`). |
| `sandbox.close(timeout=0.2)` | Graceful stop → SIGTERM; force‑kill after timeout. |
| `with psi.spawn(name, policy)` | Context manager form; sandbox closes on exit. |
| `psi.list_active() → Dict[str, Sandbox]` | Introspection. |

## 2  Executing code

```python
sb = psi.spawn("guest42", allowed_imports=["math"], numa_node=0, policy="defaults", backend="subinterpreter")
sb.exec("from math import sqrt; post(sqrt(2))")
result = sb.recv(timeout=0.1)      # 1.4142135623
```

| Method | Semantics |
|--------|-----------|
| `exec(src)` | Run source in guest. Exceptions are posted to the outbox and must be retrieved with `recv()`. |
| `call(func, *args, **kw)` | Call dotted `func` inside guest using policy-controlled module resolution. |
| `recv(timeout=None)` | Blocking receive from guest channel. |
| `post(obj)` *(guest side)* | Send picklable object to supervisor. |
| `log(level, message, **fields)` *(guest side)* | Emit a structured log event. |
| `metric(name, value, tags=None)` *(guest side)* | Emit a metric datapoint. |
| `request(capability, action, payload=None)` *(guest side)* | Ask the broker to perform a privileged action through an explicit capability. |
| `enable_tracing()` | Start recording guest operations. |
| `get_syscall_log()` | Return recorded operations. |
| `profile()` | Snapshot of current CPU and memory usage. |

## 3  Policy helpers

Policy helpers are useful for shaping prototype behavior and tests. They are not a promise of kernel enforcement in `dev` or `compatibility` mode. Use `pyisolate-doctor --mode hardened` before advertising a deployment as fail-closed.

```python
from pyisolate.policy import Policy

cust = (Policy(mem="256MiB")
        .grant(psi.ReadPath("/srv/input"),
               psi.WritePath("/srv/output"),
               psi.ConnectTCP("127.0.0.1", 9200),
               psi.Import("math"),
               psi.CpuBudget(50)))

# Legacy helpers remain available and are converted to the same authority model:
cust.allow_fs("/srv/data/*.parquet")   # read + write path authority
cust.allow_tcp("127.0.0.1:9200")
cust.allow_import("json")

sb = psi.spawn("etl", policy=cust)  # prototype policy object; not a hardened boundary unless doctor passes

# Configure token and hot-reload policies
psi.set_policy_token("secret")
policy.refresh("/tmp/policy.yml", token="secret")
```

## 4  High-level helpers

The policy names below are routing/configuration labels in the prototype release; they must not silently imply kernel-enforced isolation.

```python
@psi.sandbox(policy="ml-inference", timeout="30s", backend="subinterpreter")
def run_model(data):
    ...

pipeline = psi.Pipeline()
pipeline.add_stage("extract", policy="readonly-fs")
pipeline.add_stage("transform", policy="compute-only")
pipeline.add_stage("load", policy="write-db")
```

## 5  Metrics & events

| Property | Meaning |
|----------|---------|
| `sb.stats.cpu_ms` | CPU consumed since launch. |
| `sb.stats.mem_bytes` | Resident set size (live). |
| `psi.events` | Async iterator of `(ts, sandbox, event)` tuples. |

Event types: `MEM_KILL`, `CPU_THROTTLE`, `POLICY_HOTLOAD`, `BROKER_ERROR`.

## 5  Distributed features

| Call | Description |
|------|-------------|
| `psi.checkpoint(sb, key:bytes) -> bytes` | Serialize and encrypt sandbox state. |
| `psi.restore(blob:bytes, key:bytes) -> Sandbox` | Spawn sandbox from encrypted state. |
| `psi.migrate(sb, host:str, key:bytes) -> MigrationResponse` | Send checkpoint to `host` and restore there. |
| `policy.refresh_remote(url:str, token:str, timeout: float | None = None, max_retries: int = 0)` | Fetch YAML policy over HTTP with an optional timeout and retry budget, then apply it to prototype policy maps. Hardened deployments must fail closed if the BPF map update fails. |


## 6  Exceptions hierarchy

```python
class SandboxError(Exception): pass
class PolicyError(SandboxError): pass
class PolicyAuthError(PolicyError): pass
class TimeoutError(SandboxError): pass
class MemoryExceeded(SandboxError): pass
class CPUExceeded(SandboxError): pass
```

All user‑facing errors inherit from `SandboxError`.

## 6  Restricted subset

```python
from pyisolate import RestrictedExec

r = RestrictedExec()
r.exec("a = 1\nb = move(a)")
```

Using `a` after it is moved raises `OwnershipError`.
