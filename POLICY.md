# POLICY.md — Sandbox Policy DSL (v1.0)

> *Declarative, hot‑reloadable, kernel‑enforced.*

## 1  File layout
```yaml
version: 1.0
defaults:
  imports: [math]
sandboxes:
  base:
    fs:
      - allow: "/srv/data/**/*.csv"
      - deny:  "/srv/data/private/**"
    net:
      - connect: ["127.0.0.1:6379"]     # redis
  myguest:
    extends: base
    imports: [json]
```

* **Top‑level `defaults`** apply to every sandbox.  
* **`extends` inheritance** lets sandboxes layer on top of base policies.  
* **`sandboxes.*`** keys are user‑visible names (become `cgroup`s).

## 2  Fields

| Key | Type / unit | Semantics (enforced by eBPF) |
|-----|-------------|------------------------------|
| `fs`  | list of rules | Path globbing via **BPF‑LSM** `file_open` hook. |
| `net` | list of rules | Hooked at `cgroup/connect*`. |
| `imports` | list of module names | Import allow-list merged into sandbox runtime builtins. |
| `extends` | sandbox name | Inherit parent sandbox rules before applying local rules. |

*Rule precedence:* inherited/default rules are evaluated before child rules. Unmatched operation → **deny**.

## 3  Live reloading
`pyisolate.policy.refresh(path, token)` calls `bpftool map update` for every
changed row; the supervisor verifies *token* and new limits apply within µs—no
guest restart required.
The file is parsed and validated first.  Only after a successful parse
does `BPFManager.hot_reload()` install a new set of maps.  The previous
policy remains active until the swap completes so running sandboxes
never observe partial state.

Use `pyisolate.policy.refresh(path, token, dry_run=True)` to compile and validate
without touching live policy maps. Compiled output includes:
- `schema_version` (normalized, versioned policy schema)
- `semantics_version` (stable evaluation semantics across releases)
- `deny_log` (explicit deny entries for auditing and rollout checks)

## 4  Fallback YAML parser
If the optional **PyYAML** dependency is missing, `pyisolate.policy` falls
back to a very small parser.  It understands only two constructs:

1. `key: value` pairs on a single line (values are treated as raw strings).
2. A key followed by a list of one-level mappings:

   ```yaml
   net:
     - connect: "127.0.0.1:6379"
   ```

Anything more complex results in a `ValueError` during `refresh()`.

## 5  Extending the schema
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

## 6  Policy templates and public names

Named policies live as YAML files in the repository-level `policy/` directory.
Sandbox creation APIs resolve public string names with `pyisolate.policy.resolve_policy()`
before a `SandboxThread` is constructed. Unknown names fail closed with
`PolicyCompilerError` rather than falling back to an unconstrained sandbox.

Supported public names are:

| Public name | File | Intended use |
|-------------|------|--------------|
| `stdlib.readonly` | `policy/stdlib.readonly.yml` | Standard-library-oriented sandbox with a small import allow-list, `/tmp` filesystem access, and no outbound network. |
| `ml-inference` | `policy/ml-inference.yml` | Offline ML inference workloads with model/data paths and no outbound network by default. |
| `readonly-fs` | `policy/readonly-fs.yml` | Filesystem-focused sandbox rooted at `/tmp` with no imports or outbound network by default. |
| `ml` | `policy/ml.yml` | Legacy machine learning template loaded by filename stem. |
| `web_scraper` | `policy/web_scraper.yml` | Legacy web scraping template loaded by filename stem. |

Use a public name directly when spawning a sandbox:

```python
import pyisolate as iso

with iso.spawn("worker", policy="stdlib.readonly") as sb:
    sb.exec("import math; post(math.sqrt(16))")
```

You can still hot-reload a template with
`pyisolate.policy.refresh("policy/<name>.yml", token)` when updating live eBPF maps;
the resolver is for sandbox construction-time policy selection.
