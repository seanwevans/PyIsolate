# API.md — Public Python Interface (v 0.1)

```python
import pyisolate as psi
```

## 1  Spawning & lifecycle

| Call | Description |
|------|-------------|
| `psi.spawn(name:str, policy:str|dict=None) → Sandbox` | Create sandbox thread, attach eBPF, return handle. |
| `sandbox.close(timeout=0.2)` | Graceful stop → SIGTERM; force‑kill after timeout. |
| `psi.list_active() → Dict[str, Sandbox]` | Introspection. |

## 2  Executing code

```python
sb = psi.spawn("guest42", policy="defaults")
sb.exec("from math import sqrt; post(sqrt(2))")
result = sb.recv(timeout=0.1)      # 1.4142135623
```

| Method | Semantics |
|--------|-----------|
| `exec(src)` | Run source in guest; raises `SandboxError` on fail. |
| `call(func, *args, **kw)` | Import‑free RPC: call dotted `func` inside guest. |
| `recv(timeout=None)` | Blocking receive from guest channel. |
| `post(obj)` *(guest side)* | Send picklable object to supervisor. |

## 3  Policy helpers

```python
from pyisolate.policy import Policy

cust = (Policy(mem="256MiB")
        .allow_fs("/srv/data/*.parquet")
        .allow_tcp("127.0.0.1:9200"))

sb = psi.spawn("etl", policy=cust)
```

## 4  Metrics & events

| Property | Meaning |
|----------|---------|
| `sb.stats.cpu_ms` | CPU consumed since launch. |
| `sb.stats.mem_bytes` | Resident set size (live). |
| `psi.events` | Async iterator of `(ts, sandbox, event)` tuples. |

Event types: `MEM_KILL`, `CPU_THROTTLE`, `POLICY_HOTLOAD`, `BROKER_ERROR`.

## 5  Exceptions hierarchy

```python
class SandboxError(Exception): pass
class PolicyError(SandboxError): pass
class TimeoutError(SandboxError): pass
class MemoryExceeded(SandboxError): pass
class CPUExceeded(SandboxError): pass
```

All user‑facing errors inherit from `SandboxError`.
