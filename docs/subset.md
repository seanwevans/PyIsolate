# Restricted Subset

`pyisolate.subset.RestrictedExec` evaluates a very small dialect of Python.
Variables are move-only: once a name is passed to `move()` it can no longer be used.
Only simple assignments, expressions, and the binary operators `+`, `-`, `*`, and `/` are accepted.

Example:

```python
from pyisolate import RestrictedExec

r = RestrictedExec()
r.exec("a = 1\nb = move(a)\n")
```

Attempting to use `a` again would raise `OwnershipError`.
