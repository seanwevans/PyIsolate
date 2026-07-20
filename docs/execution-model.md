# Execution model (canonical)

A sandboxed cell has exactly **one** execution contract: the minimal cell ABI.
It is versioned in `pyisolate.runtime.protocol` as `MINIMAL_CELL_ABI` and is
frozen to seven operation names.

## Minimal cell ABI v1
The public API names the isolation backend explicitly: `backend="subinterpreter"` is the execution-cell mode, `backend="process"` is the process-boundary mode, and `backend="microvm"` is the microVM-boundary mode. These modes change the containment boundary, not the seven cell operations below.

### Backend implementation status

`subinterpreter` and `process` are implemented; `microvm` is reserved and fails
closed until a launcher is available.

The `process` backend runs guest code in a separate OS process, so in-process
Python escapes (for example recovering an unrestricted `__import__` by walking
`object.__subclasses__()`) can no longer reach the supervisor's address space —
they are confined to the guest process. Because the supervisor must never
deserialize attacker-controlled bytes, values crossing the boundary (the
argument to `post`, and `call` results) must be JSON-serializable; non-JSON
payloads surface as an error to the caller rather than crossing the boundary.
Kernel-level confinement of the guest process (no-new-privs, seccomp, rlimits,
Landlock, cgroups) is layered on top of this boundary.

## Allowed operations

1. **`exec(source)`**
   Execute source text inside the cell runtime.
2. **`call(dotted_function, *args, **kwargs)`**
   Invoke a fully-qualified function path (`module.func`) inside the cell.
3. **`post(message)`**
   Send a single picklable message to the supervisor channel.
4. **`recv(timeout=None)`**
   Receive the next item from the cell channel.
5. **`log(level, message, **fields)`**
   Emit a structured `LogEvent` on the same channel.
6. **`metric(name, value, tags=None)`**
   Emit a numeric `MetricEvent` on the same channel.
7. **`request(capability, action, payload=None)`**
   Ask the supervisor/broker to perform a privileged action through an explicit
   broker capability. If the capability was not granted, the request is rejected.

## Broker capabilities, not surface growth

The ABI deliberately does not grow new first-class operations. Filesystem,
network, subprocess, secret, clock, random, IPC, and future privileged behaviors
must be represented as explicit broker capabilities and reached through
`request(...)` or capability objects supplied by policy.

Allowed imports remain a policy-controlled implementation detail that lets
`call(module.func, ...)` and `exec(...)` resolve code. Importing is not a cell ABI
operation and must not be documented or tested as a separate guest surface.

## Non-goals (intentionally refused)

Anything outside the seven operations above is out of model and should be rejected.
In particular, we do **not** add ad-hoc host RPC, shared mutable globals, direct
privileged syscalls, implicit imports, or extra control planes.

## Why this stays small

Production safety improves when the surface area is fixed:

- policy is auditable,
- tracing is uniform,
- failure modes are bounded,
- compatibility is easier to preserve.

If a new feature cannot be expressed as one of the seven operations or as a
broker capability behind `request(...)`, it is not a cell feature.
