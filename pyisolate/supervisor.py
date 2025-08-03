"""Supervisor agent.

This module manages sandbox threads and serves as the entry point for spawning
sandboxes. It is intentionally minimal and not security hardened. Real isolation
requires eBPF enforcement which is not implemented here.
"""

from __future__ import annotations

import logging
import threading
from typing import Dict, Optional

from . import cgroup
from .bpf.manager import BPFManager
from .capabilities import ROOT, RootCapability
from .errors import PolicyAuthError
from .observability.alerts import AlertManager
from .observability.trace import Tracer
from .runtime.thread import SandboxThread
from .watchdog import ResourceWatchdog

logger = logging.getLogger(__name__)


class Sandbox:
    """Handle to a sandbox thread."""

    def __init__(self, thread: SandboxThread):
        self._thread = thread

    def exec(self, src: str) -> None:
        """Execute Python source inside the sandbox."""
        self._thread.exec(src)

    def call(self, func: str, *args, **kwargs):
        """Call a dotted function inside the sandbox."""
        return self._thread.call(func, *args, **kwargs)

    def recv(self, timeout: Optional[float] = None):
        """Receive a posted object from the sandbox."""
        return self._thread.recv(timeout)

    def close(self, timeout: float = 0.2) -> None:
        self._thread.stop(timeout)

    def enable_tracing(self) -> None:
        self._thread.enable_tracing()

    def get_syscall_log(self) -> list[str]:
        return self._thread.get_syscall_log()

    def profile(self):
        return self._thread.profile()

    # allow ``with spawn(...) as sb:`` usage
    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self):
        thread = getattr(self, "_thread", None)
        if thread is not None and thread.is_alive():
            logger.warning(
                "sandbox %s garbage-collected while still running", thread.name
            )
            try:
                self.close()
            except Exception:
                pass

    @property
    def stats(self):
        return self._thread.stats


class Supervisor:
    """Main supervisor owning all sandboxes."""

    def __init__(self, warm_pool: int = 0):
        self._sandboxes: Dict[str, SandboxThread] = {}
        self._lock = threading.Lock()
        self._alerts = AlertManager()
        self._tracer = Tracer()
        self._bpf = BPFManager()
        self._bpf.load()
        self._warm_pool: list[SandboxThread] = []
        for i in range(warm_pool):
            t = SandboxThread(name=f"warm-{i}")
            t.start()
            self._warm_pool.append(t)
        self._watchdog = ResourceWatchdog(self)
        self._watchdog.start()
        self._policy_token: str | None = None

    def register_alert_handler(self, callback) -> None:
        """Subscribe to policy violation alerts."""
        self._alerts.register(callback)

    def spawn(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        numa_node: Optional[int] = None,
    ) -> Sandbox:
        """Create and start a sandbox thread."""
        if not isinstance(name, str) or not name:
            raise ValueError("Sandbox name must be non-empty string")
        if len(name) > 64:
            raise ValueError("Sandbox name too long")
        self._cleanup()

        if policy is not None and getattr(policy, "imports", None):
            imports = set(policy.imports)
            if allowed_imports is not None:
                imports.update(allowed_imports)
            allowed_imports = list(imports)

        cg_path = cgroup.create(name, cpu_ms, mem_bytes)
        with self._lock:
            if self._warm_pool:
                thread = self._warm_pool.pop()
                thread.reset(
                    name,
                    policy=policy,
                    cpu_ms=cpu_ms,
                    mem_bytes=mem_bytes,
                    allowed_imports=allowed_imports,
                )
                thread._on_violation = self._alerts.notify
                thread._tracer = self._tracer
            else:
                thread = SandboxThread(
                    name=name,
                    policy=policy,
                    cpu_ms=cpu_ms,
                    mem_bytes=mem_bytes,
                    allowed_imports=allowed_imports,
                    on_violation=self._alerts.notify,
                    tracer=self._tracer,
                    numa_node=numa_node,
                    cgroup_path=cg_path,
                )
                thread.start()
            self._sandboxes[name] = thread
        # Remove references to any terminated sandboxes
        self._cleanup()
        return Sandbox(thread)

    def list_active(self) -> Dict[str, Sandbox]:
        """Return currently active sandboxes."""
        self._cleanup()
        with self._lock:
            return {
                name: Sandbox(t) for name, t in self._sandboxes.items() if t.is_alive()
            }

    def get_active_threads(self) -> list[SandboxThread]:
        """Return active sandbox threads for internal consumers."""
        self._cleanup()
        with self._lock:
            return [t for t in self._sandboxes.values() if t.is_alive()]

    def set_policy_token(self, token: str) -> None:
        """Configure the secret used to authenticate policy updates."""
        self._policy_token = token

    def reload_policy(self, policy_path: str, token: str | RootCapability) -> None:
        """Hot-reload policy via the BPF manager if *token* matches."""

        if isinstance(token, RootCapability):
            pass
        else:
            if self._policy_token is not None and token != self._policy_token:
                raise PolicyAuthError("invalid policy token")

        self._bpf.hot_reload(policy_path)

    def shutdown(self, cap: RootCapability = ROOT) -> None:
        """Stop watchdog and terminate all running sandboxes.

        The ``cap`` argument models a privileged capability required to shut
        down the supervisor.
        """
        self._watchdog.stop()
        with self._lock:
            sandboxes = list(self._sandboxes.values())
            warm = list(self._warm_pool)
            self._warm_pool.clear()
        for sb in sandboxes + warm:
            sb.stop()
        self._cleanup()

    def _cleanup(self) -> None:
        """Remove dead sandboxes from the registry."""
        with self._lock:
            dead = [n for n, t in self._sandboxes.items() if not t.is_alive()]
            for n in dead:
                thread = self._sandboxes[n]
                cgroup.delete(getattr(thread, "_cgroup_path", None))
                del self._sandboxes[n]
            self._warm_pool = [t for t in self._warm_pool if t.is_alive()]


_supervisor = Supervisor()


# Public API
spawn = _supervisor.spawn
list_active = _supervisor.list_active


def reload_policy(policy_path: str, token: str | RootCapability = ROOT) -> None:
    _supervisor.reload_policy(policy_path, token)


set_policy_token = _supervisor.set_policy_token


def shutdown(cap: RootCapability = ROOT) -> None:
    global _supervisor, spawn, list_active, set_policy_token
    old = _supervisor
    old.shutdown(cap)
    _supervisor = Supervisor()
    spawn = _supervisor.spawn
    list_active = _supervisor.list_active
    set_policy_token = _supervisor.set_policy_token
