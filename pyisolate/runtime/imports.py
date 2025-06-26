from __future__ import annotations

"""Capability-based import hook."""

from typing import Iterable

import builtins as _builtins

from .. import errors


class CapabilityImporter:
    """Restrict module imports to an allowed set."""

    def __init__(self, allowed: Iterable[str]):
        self._allowed = {name.split(".")[0] for name in allowed}
        self._orig_import = _builtins.__import__

    def __call__(self, name, globals=None, locals=None, fromlist=(), level=0):
        base = name.split(".")[0]
        if base not in self._allowed:
            raise errors.PolicyError(f"import of {name!r} is not permitted")
        return self._orig_import(name, globals, locals, fromlist, level)
