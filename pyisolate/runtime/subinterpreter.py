"""Real CPython sub-interpreter cells -- the ``backend="subinterpreter"`` runtime.

This is the backend the name always described. Each guest runs in its own
CPython interpreter created through :mod:`concurrent.interpreters`, with its own
``sys.modules``, its own ``builtins``, and its own module state. Compared with
``backend="thread"``, that is the whole point: the import allow-list stops being
thread-local bookkeeping inside one shared interpreter and becomes a property of
the interpreter itself, so one tenant's imports, monkey-patches and globals
cannot be observed or clobbered by another.

It is still **not** a security boundary against hostile Python. A cell shares the
supervisor's address space; ``ctypes`` imports cleanly inside one, and any C
extension can reach the whole process. Use ``backend="process"`` for code you do
not trust. What a cell buys is fault and namespace isolation between tenants
whose code is trusted but independent, plus parallelism on a GIL build.

Three properties of the underlying CPython primitive shape everything here, all
of them measured by ``scripts/cell_cost.py``:

**Creating a cell is expensive.** A sub-interpreter re-imports every module it
uses with no copy-on-write sharing, so 10 ms and 3.5 MiB bare grows to 57 ms and
13 MiB once a realistic module surface is imported. Dispatch onto an
already-warm interpreter is 0.8 ms. So cells are pooled and pre-warmed by
:class:`CellPool`, and a cell is never created on a request path if a warm one
matching the spec exists.

**A cell cannot be reset.** There is no API to return an interpreter to a
pristine state, and reusing one across tenants would leak the first tenant's
globals into the second. So the lifecycle is lease -> run -> *retire*: a
released cell is destroyed and the pool warms a replacement in the background.

**A running cell cannot be reclaimed.** ``Interpreter.close()`` raises
``InterpreterError: interpreter running``, and an async exception aimed at the
thread does not reach the interpreter actually executing. There is no
``interp.kill()``. A cell that overruns its deadline is therefore *abandoned*,
not killed: :meth:`Cell.abandon` marks it unusable and the thread stays pinned
until the process exits. The only reclaim that actually works is at the process
level, which is why a deployment that must survive runaway guests runs a pool of
worker processes and treats the worker as the kill domain.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterable, Optional

from .. import errors

logger = logging.getLogger(__name__)

#: ``concurrent.interpreters`` (PEP 734) is the supported API. The private
#: ``_interpreters`` on 3.12/3.13 is not a fallback: destroying interpreters
#: that have imported a realistic module surface (``http.client``,
#: ``email.message``) aborts the process with ``munmap_chunk(): invalid
#: pointer`` there, which is exactly the workload a cell pool generates.
MIN_PYTHON = (3, 14)

try:  # pragma: no cover - selected by the running interpreter
    import concurrent.interpreters as _interpreters

    _IMPORT_ERROR: Optional[str] = None
except ImportError as exc:  # pragma: no cover - 3.11/3.12/3.13
    _interpreters = None  # type: ignore[assignment]
    _IMPORT_ERROR = str(exc)


def is_available() -> bool:
    """Whether this build can run sub-interpreter cells."""
    return _interpreters is not None and sys.version_info[:2] >= MIN_PYTHON


def require_available() -> None:
    """Fail closed, naming what is missing, rather than degrading to a thread.

    Silently falling back to ``backend="thread"`` would hand the caller a
    different isolation model than the one they asked for, which is the mistake
    the backend rename was meant to end.
    """
    if is_available():
        return
    running = f"{sys.version_info[0]}.{sys.version_info[1]}"
    needed = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"
    detail = f" ({_IMPORT_ERROR})" if _IMPORT_ERROR else ""
    raise errors.SandboxError(
        f"backend='subinterpreter' needs CPython {needed}+ for "
        f"concurrent.interpreters; this is {running}{detail}. The private "
        "_interpreters module on 3.12/3.13 is not used as a fallback because "
        "destroying interpreters that imported a realistic module surface "
        "aborts the process there. Use backend='thread' for an in-process "
        "execution cell, or backend='process' for a real boundary."
    )


def require_available_for_fabric() -> None:
    """Same requirement as a cell, phrased for ``backend="fabric"``.

    The fabric puts cells in worker processes so a runaway one can be killed;
    it cannot invent cells on a build that has none, and degrading to threads
    would give the caller a different isolation model under the same name.
    """
    if is_available():
        return
    running = f"{sys.version_info[0]}.{sys.version_info[1]}"
    needed = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"
    raise errors.SandboxError(
        f"backend='fabric' needs CPython {needed}+ for concurrent.interpreters; "
        f"this is {running}. The fabric hosts sub-interpreter cells in worker "
        "processes, so it needs the same interpreter support a cell does. Use "
        "backend='process' for one confined process per sandbox, which is a "
        "real boundary and works on every supported Python."
    )


# --- what a warm cell contains --------------------------------------------


@dataclass(frozen=True)
class CellSpec:
    """The shape of a pre-warmed cell.

    Two cells are interchangeable only if they were warmed identically, so this
    is the pool's key. It is frozen and hashable for that reason.

    ``preimport`` is the part of the cost worth paying ahead of a request: those
    modules are imported while the cell is warming rather than when a guest
    first touches them. It must be a subset of ``allowed_imports`` -- warming a
    cell with a module its policy forbids would import it anyway.
    """

    allowed_imports: frozenset[str] = frozenset()
    preimport: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        forbidden = [m for m in self.preimport if not self.allows(m)]
        if forbidden:
            raise ValueError(
                f"preimport modules not in allowed_imports: {sorted(forbidden)}"
            )

    @classmethod
    def build(
        cls,
        allowed_imports: Optional[Iterable[str]] = None,
        preimport: Optional[Iterable[str]] = None,
    ) -> "CellSpec":
        allowed = frozenset(allowed_imports or ())
        # Default to pre-importing everything the policy allows: the import is
        # going to happen anyway, and paying for it off the request path is the
        # only reason a pool is worth having.
        chosen = (
            tuple(sorted(preimport))
            if preimport is not None
            else tuple(sorted(allowed))
        )
        return cls(allowed_imports=allowed, preimport=chosen)

    def allows(self, name: str) -> bool:
        """Mirror of the thread backend's allow-list semantics."""
        if name in self.allowed_imports:
            return True
        # ``import package.child`` imports ``package`` first, so a parent is
        # allowed exactly when something more specific under it is.
        return any(a.startswith(f"{name}.") for a in self.allowed_imports)


#: CPython's own cross-interpreter machinery imports these from inside the cell.
#: A ``Queue`` falls back to ``pickle`` for anything not natively shareable, and
#: ``Interpreter.exec`` uses ``pickle``/``traceback`` to carry a guest exception
#: back to the caller. Those imports go through whatever ``__import__`` the cell
#: currently has, so an allow-list that does not include them does not produce a
#: policy denial -- it produces ``NotShareableError`` from the runtime, with the
#: real cause two layers down. The allow-list gates *guest* imports; starving the
#: interpreter's own plumbing is not a security control.
_RUNTIME_IMPORTS = ("pickle", "traceback", "copyreg")

#: Installed in every cell before any guest code runs. It executes inside the
#: cell's own interpreter, so it rebinds *that* interpreter's ``builtins`` --
#: the supervisor's is untouched, which is what makes the allow-list a property
#: of the interpreter instead of thread-local state.
#:
#: Every message is JSON-encoded here, in the cell, and crosses as one ``str``.
#: A ``str`` is natively shareable, so the queue's pickle fallback never
#: engages and the supervisor never unpickles bytes the guest produced. That is
#: the same rule the process backend applies to values crossing its boundary,
#: and it is enforced at the point of the call: a guest that posts something
#: unserialisable gets a ``TypeError`` from ``post`` rather than an opaque
#: sharing error from the runtime.
_BOOTSTRAP = """
import builtins as _pyi_builtins
import json as _pyi_json

_PYI_ALLOWED = frozenset(__pyi_allowed__)
_PYI_RUNTIME = frozenset(__pyi_runtime_imports__)
_pyi_real_import = _pyi_builtins.__import__
_pyi_outbox = __pyi_outbox__


def _pyi_is_allowed(name):
    if name in _PYI_ALLOWED or name in _PYI_RUNTIME:
        return True
    prefix = name + "."
    for allowed in _PYI_ALLOWED:
        if allowed.startswith(prefix):
            return True
    return False


def _pyi_import(name, globals=None, locals=None, fromlist=(), level=0):
    requested = name
    if level:
        package = globals.get("__package__") if isinstance(globals, dict) else None
        base = (package or "")
        if level > 1:
            base = base.rsplit(".", level - 1)[0]
        requested = base + "." + name if name else base
    if not _pyi_is_allowed(requested):
        raise ImportError("import of %r is not permitted by policy" % (requested,))
    return _pyi_real_import(name, globals, locals, fromlist, level)


def _pyi_emit(kind, payload):
    _pyi_outbox.put(_pyi_json.dumps([kind, payload]))


def post(value):
    # Send a value to the supervisor. Must be JSON-serialisable.
    _pyi_emit("post", value)


def log(level, message, **fields):
    _pyi_emit("log", {"level": str(level), "message": str(message), "fields": fields})


def metric(name, value):
    _pyi_emit("metric", {"name": str(name), "value": value})


def request(capability, *args, **kwargs):
    # Ask the broker to perform a privileged operation for this cell.
    _pyi_emit(
        "request",
        {"capability": str(capability), "args": list(args), "kwargs": kwargs},
    )


_pyi_builtins.post = post
_pyi_builtins.log = log
_pyi_builtins.metric = metric
_pyi_builtins.request = request
# Installed last: everything above needs a working import.
_pyi_builtins.__import__ = _pyi_import
"""


class CellState(str, Enum):
    """Lifecycle of one cell. There is no path back from ABANDONED."""

    WARMING = "warming"
    IDLE = "idle"
    RUNNING = "running"
    RETIRED = "retired"
    ABANDONED = "abandoned"


class Cell:
    """One CPython sub-interpreter plus the queue it reports through."""

    __slots__ = ("_interp", "_outbox", "_spec", "_state", "_lock", "_created_at")

    def __init__(self, spec: CellSpec) -> None:
        require_available()
        self._spec = spec
        self._state = CellState.WARMING
        self._lock = threading.Lock()
        self._created_at = time.monotonic()
        self._interp = _interpreters.create()
        self._outbox = _interpreters.create_queue()
        self._bootstrap()

    def _bootstrap(self) -> None:
        self._interp.prepare_main(
            __pyi_outbox__=self._outbox,
            __pyi_allowed__=tuple(sorted(self._spec.allowed_imports)),
            __pyi_runtime_imports__=_RUNTIME_IMPORTS,
        )
        self._interp.exec(_BOOTSTRAP)
        for module in self._spec.preimport:
            # Warming failures are not fatal: a module the host cannot import
            # into a sub-interpreter (numpy and cryptography both refuse) must
            # surface when the guest asks for it, not turn the pool into a
            # source of startup errors.
            try:
                self._interp.exec(f"import {module}")
            except Exception as exc:  # pragma: no cover - depends on host
                logger.warning(
                    "cell pre-import of %r failed; it will fail for the guest "
                    "too: %s",
                    module,
                    exc,
                )
        self._state = CellState.IDLE

    # --- introspection ---

    @property
    def spec(self) -> CellSpec:
        return self._spec

    @property
    def state(self) -> CellState:
        return self._state

    @property
    def id(self) -> int:
        return self._interp.id

    def is_usable(self) -> bool:
        return self._state in (CellState.IDLE, CellState.RUNNING)

    def _is_running(self) -> bool:
        """Whether the runtime considers the interpreter to be executing."""
        try:
            return bool(self._interp.is_running())
        except Exception:  # pragma: no cover - a destroyed interpreter
            return False

    # --- the cell ABI ---

    def exec(self, source: str) -> None:
        """Run *source* in the cell. Raises the guest's exception on failure."""
        self._enter()
        try:
            self._interp.exec(source)
        finally:
            self._leave()

    def call(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Call *func* inside the cell and return its result."""
        self._enter()
        try:
            return self._interp.call(func, *args, **kwargs)
        finally:
            self._leave()

    def exec_in_thread(self, source: str) -> threading.Thread:
        """Run *source* on a thread of its own so the caller can time it out.

        The returned thread is the only handle on that work. If it overruns,
        there is nothing to cancel -- see :meth:`abandon`.
        """
        self._enter()

        def _run() -> None:
            try:
                self._interp.exec(source)
            except BaseException:  # pragma: no cover - surfaced via drain
                logger.debug("cell %s raised in exec_in_thread", self.id, exc_info=True)
            finally:
                self._leave()

        thread = threading.Thread(target=_run, name=f"pyisolate-cell-{self.id}")
        thread.daemon = True
        thread.start()
        return thread

    def drain(self) -> list[tuple[str, Any]]:
        """Return every ``(kind, payload)`` the cell has emitted so far."""
        messages: list[tuple[str, Any]] = []
        while True:
            try:
                raw = self._outbox.get_nowait()
            except Exception:
                return messages
            decoded = self._decode(raw)
            if decoded is not None:
                messages.append(decoded)

    @staticmethod
    def _decode(raw: Any) -> Optional[tuple[str, Any]]:
        """Parse one cell message, dropping anything malformed.

        Only JSON produced by the bootstrap is expected. Guest code can reach
        the outbox and put whatever it likes on it, so this validates rather
        than trusts: a malformed frame is logged and discarded instead of
        propagating an arbitrary object into the supervisor.
        """
        if not isinstance(raw, str):
            logger.warning("discarding non-string cell message %r", type(raw))
            return None
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            logger.warning("discarding unparseable cell message")
            return None
        if (
            not isinstance(parsed, list)
            or len(parsed) != 2
            or not isinstance(parsed[0], str)
        ):
            logger.warning("discarding malformed cell message")
            return None
        return parsed[0], parsed[1]

    # --- lifecycle ---

    def _enter(self) -> None:
        with self._lock:
            if self._state is CellState.ABANDONED:
                raise errors.SandboxError("cell was abandoned and cannot be reused")
            if self._state is CellState.RETIRED:
                raise errors.SandboxError("cell was retired and cannot be reused")
            self._state = CellState.RUNNING

    def _leave(self) -> None:
        with self._lock:
            if self._state is CellState.RUNNING:
                self._state = CellState.IDLE

    def retire(self) -> bool:
        """Destroy the interpreter. Returns whether it actually went away.

        This is the only way to make a cell safe to hand to another tenant:
        there is no reset, so a cell that has run one tenant's code is spent.
        """
        with self._lock:
            if self._state in (CellState.RETIRED, CellState.ABANDONED):
                return self._state is CellState.RETIRED
        # Ask the runtime, not our own state flag. ``exec_in_thread`` marks the
        # cell RUNNING before its thread has actually entered the interpreter,
        # and closing one that a thread is inside is not a catchable error:
        # CPython aborts the whole process with "Py_EndInterpreter: not the
        # last thread". Refusing here keeps a lost cell from taking every other
        # tenant in the process down with it.
        if self._is_running():
            logger.warning("cell %s is still running; cannot retire it", self.id)
            with self._lock:
                self._state = CellState.ABANDONED
            return False
        try:
            self._interp.close()
        except Exception as exc:
            # Lost the race anyway: the guest re-entered between the check and
            # the close. Record it rather than pretending the cell closed.
            logger.warning("cell %s could not be retired: %s", self.id, exc)
            with self._lock:
                self._state = CellState.ABANDONED
            return False
        with self._lock:
            self._state = CellState.RETIRED
        return True

    def abandon(self, reason: str) -> None:
        """Mark a cell unusable without claiming it was reclaimed.

        Called when a guest overruns its deadline. The interpreter keeps
        running and its thread stays pinned for the life of the process; the
        honest accounting is that the cell is lost, not killed.
        """
        with self._lock:
            self._state = CellState.ABANDONED
        logger.warning("cell %s abandoned: %s", self.id, reason)

    def kill(self, timeout: float = 0.2) -> bool:
        """Always ``False`` while the cell is running. CPython has no kill.

        Kept so the backend answers the same question as the others rather than
        raising ``AttributeError``, and so callers see the ``False`` and
        escalate to the process level instead of assuming a stopped guest.
        """
        del timeout
        if self._state is CellState.RUNNING:
            return False
        return self.retire()


# --- the pool -------------------------------------------------------------


@dataclass
class PoolStats:
    """Counters that make the pool's behaviour legible in production."""

    created: int = 0
    reused: int = 0
    retired: int = 0
    abandoned: int = 0
    warm: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "created": self.created,
            "reused": self.reused,
            "retired": self.retired,
            "abandoned": self.abandoned,
            "warm": self.warm,
        }


class CellPool:
    """Keeps pre-warmed cells so a request pays 0.8 ms rather than 10-57 ms.

    Cells are keyed by :class:`CellSpec`, because a warm cell is only useful to
    a guest that wants exactly the module surface it was warmed with. Handing
    back a cell warmed for a different policy would either import the missing
    modules on the request path -- losing the point -- or run the guest against
    an allow-list that is not its own.
    """

    def __init__(self, warm_per_spec: int = 1, max_warm: int = 32) -> None:
        if warm_per_spec < 0:
            raise ValueError("warm_per_spec must be >= 0")
        if max_warm < 0:
            raise ValueError("max_warm must be >= 0")
        self._warm_per_spec = warm_per_spec
        self._max_warm = max_warm
        self._warm: dict[CellSpec, list[Cell]] = {}
        self._lock = threading.Lock()
        self._stats = PoolStats()
        self._closed = False
        # Warming runs on background threads. They must be tracked, because
        # creating or destroying a sub-interpreter while the runtime is
        # finalising is not safe: close() joins them before retiring anything.
        self._warming: set[threading.Thread] = set()

    # --- lease/return ---

    def acquire(self, spec: CellSpec) -> Cell:
        """Return a cell matching *spec*, warm if one is available."""
        with self._lock:
            if self._closed:
                raise errors.SandboxError("cell pool is closed")
            waiting = self._warm.get(spec)
            while waiting:
                cell = waiting.pop()
                if cell.is_usable():
                    self._stats.reused += 1
                    self._stats.warm = self._count_warm_locked()
                    return cell
        return self._create(spec)

    def release(self, cell: Cell) -> None:
        """Retire *cell* and warm a replacement.

        Deliberately not a return-to-pool: an interpreter cannot be reset, so
        reusing one across tenants would carry the first tenant's globals into
        the second.
        """
        retired = cell.retire()
        with self._lock:
            if retired:
                self._stats.retired += 1
            else:
                self._stats.abandoned += 1
            closed = self._closed
        if not closed and retired:
            self._refill(cell.spec)

    def abandon(self, cell: Cell, reason: str) -> None:
        """Record a cell that overran and cannot be taken back."""
        cell.abandon(reason)
        with self._lock:
            self._stats.abandoned += 1

    # --- warming ---

    def prewarm(self, spec: CellSpec, count: Optional[int] = None) -> int:
        """Create warm cells for *spec* up front. Returns how many were added."""
        target = self._warm_per_spec if count is None else count
        added = 0
        for _ in range(target):
            if not self._has_warm_capacity():
                break
            cell = self._create(spec)
            with self._lock:
                if self._closed:
                    # Closed while this cell was being built. Retire it here
                    # rather than parking it in a pool nobody will drain.
                    closed = True
                else:
                    self._warm.setdefault(spec, []).append(cell)
                    self._stats.warm = self._count_warm_locked()
                    closed = False
            if closed:
                cell.retire()
                break
            added += 1
        return added

    def _refill(self, spec: CellSpec) -> None:
        """Warm a replacement off the request path."""
        if self._warm_per_spec <= 0:
            return

        def _warm() -> None:
            try:
                self.prewarm(spec, 1)
            except Exception:  # pragma: no cover - best effort
                logger.warning("failed to warm a replacement cell", exc_info=True)
            finally:
                with self._lock:
                    self._warming.discard(threading.current_thread())

        thread = threading.Thread(target=_warm, name="pyisolate-cell-warm")
        # Daemon so a wedged warm never blocks interpreter exit; close() still
        # joins it, so the normal path does not race teardown.
        thread.daemon = True
        with self._lock:
            if self._closed:
                return
            self._warming.add(thread)
        thread.start()

    def _has_warm_capacity(self) -> bool:
        with self._lock:
            if self._closed:
                return False
            return self._count_warm_locked() < self._max_warm

    def _count_warm_locked(self) -> int:
        return sum(len(cells) for cells in self._warm.values())

    def _create(self, spec: CellSpec) -> Cell:
        cell = Cell(spec)
        with self._lock:
            self._stats.created += 1
        return cell

    # --- teardown ---

    def stats(self) -> dict[str, int]:
        with self._lock:
            self._stats.warm = self._count_warm_locked()
            return self._stats.as_dict()

    def close(self, timeout: float = 5.0) -> None:
        """Retire every warm cell. Abandoned ones cannot be reclaimed.

        In-flight warm threads are joined first. Creating an interpreter
        concurrently with the runtime tearing one down is not safe, so closing
        without waiting turns an orderly shutdown into a race.
        """
        with self._lock:
            self._closed = True
            warming = list(self._warming)
        deadline = time.monotonic() + timeout
        for thread in warming:
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive():  # pragma: no cover - needs a wedged warm
                logger.warning(
                    "warm thread %s did not finish before close", thread.name
                )
        with self._lock:
            warm = [cell for cells in self._warm.values() for cell in cells]
            self._warm.clear()
            self._warming.clear()
        for cell in warm:
            if not cell.retire():  # pragma: no cover - needs a stuck cell
                with self._lock:
                    self._stats.abandoned += 1

    def __enter__(self) -> "CellPool":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --- the sandbox handle ---------------------------------------------------


@dataclass
class _Deadline:
    wall_time_ms: Optional[int] = None

    def seconds(self) -> Optional[float]:
        if self.wall_time_ms is None:
            return None
        return self.wall_time_ms / 1000.0


class SubinterpreterSandbox:
    """Sandbox handle over a pooled cell, exposing the minimal cell ABI."""

    def __init__(
        self,
        name: str,
        *,
        pool: CellPool,
        spec: CellSpec,
        wall_time_ms: Optional[int] = None,
    ) -> None:
        require_available()
        self.name = name
        self._pool = pool
        self._spec = spec
        self._deadline = _Deadline(wall_time_ms)
        self._cell: Optional[Cell] = pool.acquire(spec)
        self._posted: list[Any] = []
        self._logs: list[Any] = []
        self._metrics: list[Any] = []
        self._requests: list[Any] = []
        self._lock = threading.Lock()
        self._backend = "subinterpreter"
        # Read directly by the Sandbox handle. A cell is not in a cgroup of its
        # own -- it shares the supervisor's process -- and its quotas are the
        # wall-time deadline only, which is what these report.
        self._cgroup_path: Optional[str] = None
        self._quarantine_reason: Optional[str] = None
        self.termination_reason: Optional[str] = None
        self.quota_enforcement = "wall_time_only"

    # --- ABI ---

    def exec(self, src: str) -> None:
        cell = self._require_cell()
        timeout = self._deadline.seconds()
        if timeout is None:
            cell.exec(src)
            self._collect(cell)
            return
        thread = cell.exec_in_thread(src)
        thread.join(timeout)
        if thread.is_alive():
            # Nothing can stop it. Give up the cell and say so plainly.
            self._pool.abandon(cell, f"exec exceeded {self._deadline.wall_time_ms}ms")
            self._cell = None
            raise errors.WallTimeExceeded(
                f"sandbox '{self.name}' exceeded "
                f"{self._deadline.wall_time_ms}ms; the cell was abandoned "
                "because a running sub-interpreter cannot be reclaimed"
            )
        self._collect(cell)

    def call(
        self,
        func: str,
        *args: Any,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> Any:
        """Call a dotted function inside the cell and return its result.

        Takes a dotted *name*, matching the other backends, rather than a
        callable. Resolving it inside the cell keeps the host from pickling one
        of its own objects into the guest, and routes the lookup through the
        cell's guarded ``__import__`` so the allow-list applies to it.
        """
        del timeout  # honoured by exec's deadline, not per-call
        cell = self._require_cell()
        if not isinstance(func, str) or not func:
            raise TypeError("func must be a dotted name")
        module, _, attr = func.rpartition(".")
        if not module or not attr:
            raise ValueError(f"expected a dotted name, got {func!r}")
        # Reuse the decoder the bootstrap already bound. Importing json here
        # would go through the guarded __import__ and be denied unless the
        # policy happened to allow it, which has nothing to do with the call.
        payload = json.dumps({"args": list(args), "kwargs": kwargs})
        cell.exec(
            f"_pyi_call = _pyi_json.loads({payload!r})\n"
            f"_pyi_mod = __import__({module!r}, fromlist=[{attr!r}])\n"
            f"post(getattr(_pyi_mod, {attr!r})"
            "(*_pyi_call['args'], **_pyi_call['kwargs']))\n"
        )
        self._collect(cell)
        with self._lock:
            if not self._posted:
                raise errors.SandboxError(f"call to {func!r} returned no result")
            return self._posted.pop()

    # --- surface the Sandbox handle delegates to ---

    def cancel(self, timeout: float = 0.2) -> bool:
        """Same answer as :meth:`kill`: there is nothing else to try."""
        return self.kill(timeout)

    def reap(self) -> bool:
        self.close()
        return True

    def quarantine(self, reason: str = "manual quarantine") -> None:
        cell = self._cell
        self._quarantine_reason = reason
        if cell is not None:
            self._pool.abandon(cell, reason)
            self._cell = None

    def snapshot(self) -> dict[str, Any]:
        """Serializable state for checkpointing.

        Deliberately excludes guest state: an interpreter's contents cannot be
        captured or restored, so a checkpoint of a cell is its configuration,
        not its memory.
        """
        return {
            "name": self.name,
            "backend": self._backend,
            "allowed_imports": sorted(self._spec.allowed_imports),
            "wall_time_ms": self._deadline.wall_time_ms,
        }

    def reset_config(self) -> dict[str, Any]:
        raise NotImplementedError(
            "a sub-interpreter cannot be reset to a pristine state, so a cell "
            "is never reused across tenants. Close this sandbox and spawn "
            "another; the pool keeps a warm cell so that costs ~1ms."
        )

    def reset(self, *args: Any, **kwargs: Any) -> None:
        self.reset_config()

    def enable_tracing(self) -> None:
        raise NotImplementedError(
            "syscall tracing is a process-backend feature; a cell shares the "
            "supervisor's process and has no syscall boundary to trace"
        )

    def get_syscall_log(self) -> list[str]:
        return []

    def get_denial_events(self) -> list[dict[str, str]]:
        """Import denials are raised into the guest, not collected here."""
        return []

    def profile(self) -> dict[str, Any]:
        return self.stats()

    def recv(self, timeout: Optional[float] = None) -> Any:
        with self._lock:
            if self._posted:
                return self._posted.pop(0)
        cell = self._require_cell()
        deadline = time.monotonic() + (timeout if timeout is not None else 0.0)
        while True:
            self._collect(cell)
            with self._lock:
                if self._posted:
                    return self._posted.pop(0)
            if timeout is None or time.monotonic() >= deadline:
                raise errors.TimeoutError(f"no message from sandbox '{self.name}'")
            time.sleep(0.001)

    # --- supervisor surface ---

    def is_alive(self) -> bool:
        cell = self._cell
        return cell is not None and cell.is_usable()

    def kill(self, timeout: float = 0.2) -> bool:
        cell = self._cell
        if cell is None:
            return True
        return cell.kill(timeout)

    def stop(self, timeout: float = 0.2) -> None:
        self.close(timeout)

    def close(self, timeout: float = 0.2) -> None:
        del timeout
        cell = self._cell
        self._cell = None
        if cell is not None:
            self._pool.release(cell)

    def stats(self) -> dict[str, Any]:
        cell = self._cell
        return {
            "backend": self._backend,
            "cell_id": None if cell is None else cell.id,
            "cell_state": None if cell is None else cell.state.value,
            "posted": len(self._posted),
            "requests": len(self._requests),
            "pool": self._pool.stats(),
        }

    def get_broker_requests(self) -> list[Any]:
        """Requests the guest raised, for the supervisor's broker to mediate."""
        with self._lock:
            return list(self._requests)

    def __enter__(self) -> "SubinterpreterSandbox":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- internals ---

    def _require_cell(self) -> Cell:
        cell = self._cell
        if cell is None or not cell.is_usable():
            raise errors.SandboxError(f"sandbox '{self.name}' has no usable cell")
        return cell

    def _collect(self, cell: Cell) -> None:
        for kind, payload in cell.drain():
            with self._lock:
                if kind == "post":
                    self._posted.append(payload)
                elif kind == "log":
                    self._logs.append(payload)
                elif kind == "metric":
                    self._metrics.append(payload)
                elif kind == "request":
                    self._requests.append(payload)
                else:
                    logger.warning("unknown cell message kind %r", kind)


#: Process-wide pool, created lazily so importing this module on a build
#: without sub-interpreters stays free.
_default_pool: Optional[CellPool] = None
_default_pool_lock = threading.Lock()


def default_pool() -> CellPool:
    global _default_pool
    with _default_pool_lock:
        if _default_pool is None:
            require_available()
            _default_pool = CellPool()
        return _default_pool


def reset_default_pool() -> None:
    """Drop the process-wide pool. Used by tests and by supervisor shutdown."""
    global _default_pool
    with _default_pool_lock:
        pool, _default_pool = _default_pool, None
    if pool is not None:
        pool.close()


__all__ = [
    "MIN_PYTHON",
    "Cell",
    "CellPool",
    "CellSpec",
    "CellState",
    "PoolStats",
    "SubinterpreterSandbox",
    "default_pool",
    "is_available",
    "require_available",
    "require_available_for_fabric",
    "reset_default_pool",
]
