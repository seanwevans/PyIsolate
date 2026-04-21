# Extension-module compatibility matrix (CPython 3.13 free-threaded)

PyIsolate runs guest code inside subinterpreters on a `--disable-gil` CPython 3.13 runtime. That means module compatibility has **two** independent checks:

1. **Subinterpreter-safe**: can the module be imported/used in multiple subinterpreters without shared global-state hazards?
2. **Free-threaded-safe**: can the module run correctly without the process-wide GIL?

Use this matrix to decide what goes into `allowed_imports` and what must be blocked by policy.

## Status key

- ✅ **Yes**: generally acceptable in PyIsolate sandboxes.
- ⚠️ **Conditional**: usable with constraints or with version pinning + stress tests.
- ❌ **No**: deny by default (banned/unsafe).

## Compatibility matrix

| Module/package class | Examples | Subinterpreter-safe | Free-threaded-safe | Banned/unsafe in PyIsolate | Notes |
| --- | --- | --- | --- | --- | --- |
| Stdlib pure-Python modules | `json`, `pathlib`, `itertools` wrappers, `dataclasses`, `typing` | ✅ | ✅ | No | Preferred default set for untrusted guest code. |
| Stdlib modules that touch process-wide state | `signal`, `faulthandler`, `warnings` (global filters), `locale` | ⚠️ | ⚠️ | Often | Allow only when sandbox behavior is deterministic and isolated effects are acceptable. |
| Stdlib modules with direct OS/process control | `os`, `subprocess`, `ctypes`, `resource`, `socket` | ⚠️ | ⚠️ | Frequently | Not inherently incompatible with 3.13, but usually policy-denied in PyIsolate because they can bypass sandbox intent. |
| Pure Python third-party packages | Most packages with no native extension (for example utility libs) | ✅ | ✅ | No | Usually the safest non-stdlib option; still require memory/CPU limits and import allowlisting. |
| C/Rust extensions that are explicitly subinterpreter + no-GIL audited | Newer extension releases that document per-interpreter module state and no-GIL support | ✅ | ✅ | No | Require documented support and pinned versions. Add to allowlist only after soak tests. |
| C/Rust extensions that are thread-safe but not subinterpreter-safe | Legacy single-phase init modules with hidden globals | ❌ | ⚠️ | Yes | Deny by default; can corrupt state across sandboxes. |
| C/Rust extensions that are subinterpreter-safe but not no-GIL safe | Extensions relying on implicit GIL serialization | ⚠️ | ❌ | Yes | Deny in free-threaded runtime. |
| C extensions with known global mutable state / unsafe callbacks | Older numeric, image, DB, crypto bindings without explicit 3.13 support | ❌ | ❌ | Yes | Treat as banned until upstream provides explicit compatibility guarantees. |
| FFI and dynamic loader surfaces | `ctypes`, `cffi` dynamic loading, custom `dlopen` wrappers | ❌ | ❌ | Yes | High-risk escape surface; deny for sandboxed tenants. |

## Operational policy in PyIsolate

1. **Default-allow only stdlib pure-Python modules** for new tenant policies.
2. **Require evidence** before allowing native extensions:
   - Upstream docs claim subinterpreter support.
   - Upstream docs claim free-threaded / no-GIL support for 3.13.
   - Reproducible stress test under concurrent sandboxes.
3. **Pin package versions** in policy-controlled environments to avoid silent ABI/behavior drift.
4. **Block dynamic native loading** (`ctypes`/`cffi`) unless the tenant is trusted and isolated with additional guardrails.
5. **Re-validate on every Python minor bump** (for example 3.13.x → 3.14) and on each extension upgrade.

## Recommended allow/deny workflow

1. Start from a minimal `allowed_imports` list.
2. Classify each requested module using this matrix.
3. For ⚠️ items, run compatibility tests in a staging cluster:
   - import in many subinterpreters,
   - concurrent execution under load,
   - repeated teardown/recreate cycles.
4. Promote to ✅ only after stable test runs and metrics review.
5. Keep ❌ items in a central denylist policy.
