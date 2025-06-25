# POLICY.md — Sandbox Policy DSL (v 0.1)

> *Declarative, hot‑reloadable, kernel‑enforced.*

## 1  File layout
```yaml
version: 0.1
defaults:
  fs: readonly
  net: none
  mem: 64MiB
  cpu: 200ms
sandboxes:
  myguest:
    fs:
      - allow: "/srv/data/**/*.csv"
      - deny:  "/srv/data/private/**"
    net:
      - connect: ["127.0.0.1:6379"]     # redis
    mem: 128MiB
    cpu: 500ms
```

* **Top‑level `defaults`** apply to every sandbox unless overridden.  
* **`sandboxes.*`** keys are user‑visible names (become `cgroup`s).

## 2  Fields

| Key | Type / unit | Semantics (enforced by eBPF) |
|-----|-------------|------------------------------|
| `fs`  | `readonly` \| `none` \| list of rules | Path globbing via **BPF‑LSM** `file_open` hook. Wildcards use `**/`. |
| `net` | `none` \| list of rules | Hooked at `cgroup/connect*`; tuples `["ip:port", "tcp/udp"]`. |
| `mem` | `<N>MiB` | Hard cap, checked in allocator; guest killed on exceed. |
| `cpu` | `<N>ms` per 100 ms window | Perf‑event counter → SIGXCPU to offending thread. |

*Rule precedence:* first match wins. Unmatched operation → **deny**.

## 3  Live reloading
`pyisolate.policy.refresh(path)` calls `bpftool map update` for every
changed row; new limits apply within µs—no guest restart required.
The file is parsed and validated first.  Only after a successful parse
does `BPFManager.hot_reload()` install a new set of maps.  The previous
policy remains active until the swap completes so running sandboxes
never observe partial state.

## 4  Extending the schema
Add custom keys by shipping a new eBPF object and registering a
`PolicyPlugin`:

```python
from pyisolate.policy import register_plugin

class IpcLimiter(PolicyPlugin):
    key = "ipc"

    def on_attach(self, cgid, value):
        # value e.g. "pipes:4"
        attach_bpf_prog("ipc_guard", cgid, parse_limit(value))

register_plugin(IpcLimiter)
```
