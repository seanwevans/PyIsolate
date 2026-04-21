# Execution model (canonical)

A sandboxed cell has exactly **one** execution contract.

## Allowed operations

1. **`exec(source)`**
   Execute source text inside the cell runtime.
2. **`call(dotted_function, *args, **kwargs)`**
   Invoke a fully-qualified function path (`module.func`) inside the cell.
3. **`import module`**
   Import only modules allowed by policy (`allowed_imports` + policy imports).
4. **`post(message)`**
   Send a single picklable message to the supervisor channel.
5. **`stream logs`**
   Emit structured log events as messages on the same channel (log envelope).
6. **`emit metrics`**
   Emit metric datapoints as messages on the same channel (metric envelope).
7. **`request broker actions`**
   Ask the supervisor/broker to perform privileged actions by posting broker request envelopes.

## Non-goals (intentionally refused)

Anything outside the seven operations above is out of model and should be rejected.
In particular, we do **not** add ad-hoc host RPC, shared mutable globals, direct privileged syscalls,
or extra control planes.

## Why this stays small

Production safety improves when the surface area is fixed:

- policy is auditable,
- tracing is uniform,
- failure modes are bounded,
- compatibility is easier to preserve.

If a new feature cannot be expressed as one of the seven operations, it is not a cell feature.
