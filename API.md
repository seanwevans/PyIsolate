# API.md — Public Python Interface (v 0.1)

```python
import pyisolate as psi
```

## 1  Spawning & lifecycle

| Call | Description |
|------|-------------|
| `psi.spawn(name:str, policy:str|dict=None, allowed_imports:list[str]|None=None) → Sandbox` | Create sandbox thread, attach eBPF, return handle with module whitelist. |
| `sandbox.close(timeout=0.2)` | Graceful stop → SIGTERM; force‑kill after timeout. |
| `with psi.spawn(name, policy)` | Context manager form; sandbox closes on exit. |
| `psi.list_active() → Dict[str, Sandbox]` | Introspection. |

## 2  Executing code

```python
sb = psi.spawn("guest42", policy="defaults", numa_node=0)
sb.exec("from math import sqrt; post(sqrt(2))")
result = sb.recv(timeout=0.1)      # 1.4142135623
```

| Method | Semantics |
|--------|-----------|
| `exec(src)` | Run source in guest. Exceptions are posted to the outbox and must be retrieved with `recv()`. |
| `call(func, *args, **kw)` | Import‑free RPC: call dotted `func` inside guest. |
| `recv(timeout=None)` | Blocking receive from guest channel. |
| `post(obj)` *(guest side)* | Send picklable object to supervisor. |
| `enable_tracing()` | Start recording guest operations. |
| `get_syscall_log()` | Return recorded operations. |
| `profile()` | Snapshot of current CPU and memory usage. |

## 3  Policy helpers

```python
from pyisolate.policy import Policy

cust = (Policy(mem="256MiB")
        .allow_fs("/srv/data/*.parquet")
        .allow_tcp("127.0.0.1:9200")
        .allow_import("math"))

# Lists of accumulated permissions are available via `fs` and `tcp`:
cust.fs  # ["/srv/data/*.parquet"]
cust.tcp # ["127.0.0.1:9200"]


sb = psi.spawn("etl", policy=cust)

# Configure token and hot-reload policies
psi.set_policy_token("secret")
policy.refresh("/tmp/policy.yml", token="secret")
```

## 4  High-level helpers

```python
@psi.sandbox(policy="ml-inference", timeout="30s")
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
| `psi.migrate(sb, host:str, key:bytes) -> Sandbox` | Send checkpoint to `host` and restore there. |
| `policy.refresh_remote(url:str, token:str)` | Fetch YAML policy over HTTP and apply. |


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
