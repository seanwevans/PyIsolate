"""Sandbox thread implementation.

This is a greatly simplified placeholder that executes code in a dedicated
thread using the standard interpreter. Real isolation would leverage
sub‑interpreters and eBPF enforcement as outlined in AGENTS.md.
"""

from __future__ import annotations

import builtins
import ctypes
import fnmatch
import io
import logging
import os
import queue
import random
import secrets as pysecrets
import signal
import socket
import subprocess
import sys
import threading
import time
import tracemalloc
import types
import weakref
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from .. import errors
from ..capabilities import (
    AuthoritySet,
    ClockCapability,
    ConnectTCP,
    CpuBudget,
    Import,
    FilesystemCapability,
    NetworkCapability,
    RandomCapability,
    ReadPath,
    SecretCapability,
    SubprocessCapability,
    WritePath,
)
from .protocol import (
    AttachCgroupRequest,
    BrokerRequest,
    CallRequest,
    ExecRequest,
    LogEvent,
    MetricEvent,
    StopRequest,
)
from ..numa import bind_current_thread
from ..observability.trace import Tracer
from ..telemetry import DenialEvent
from ..policy.model import RuntimePolicy, from_sandbox_policy

_thread_local = threading.local()

_ORIG_OPEN = builtins.open
_ORIG_SOCKET_CONNECT = socket.socket.connect
_ORIG_SOCKET_CONNECT_EX = socket.socket.connect_ex
_ORIG_SOCKET_SENDTO = socket.socket.sendto
_ORIG_THREAD_START = threading.Thread.start
_ORIG_OS_OPEN = os.open
_CAPABILITY_MARKER = "__pyisolate_capability__"
# No modules are imported by default. Examples and tests must name every
# module they need via Policy.allow_import(...) or allowed_imports=[...].
# Keeping this empty makes missing import policy fail closed instead of
# falling back to unrestricted Python imports.
DEFAULT_ALLOWED_IMPORTS: frozenset[str] = frozenset()
_BLOCKED_MODULES = {"ctypes", "multiprocessing"}


def _active_sandbox() -> "SandboxThread | None":
    return getattr(_thread_local, "sandbox", None)


def _deny(
    capability: str,
    attempted_action: str,
    policy_rule: str,
    message: str,
    *,
    kernel_decision: str = "not_evaluated",
    broker_decision: str = "deny",
) -> errors.PolicyError:
    sandbox = _active_sandbox()
    cell = sandbox.name if sandbox is not None else "<unknown>"
    event = DenialEvent(
        cell=cell,
        capability=capability,
        attempted_action=attempted_action,
        policy_rule=policy_rule,
        kernel_decision=kernel_decision,
        broker_decision=broker_decision,
    )
    if sandbox is not None:
        sandbox._record_denial(event)
    return errors.PolicyError(message, denial_event=event)


def _format_roots(roots: Iterable[Path]) -> str:
    return ",".join(str(root) for root in roots)


def _subprocess_command_name(args: object) -> str | None:
    if isinstance(args, str):
        return args.split(maxsplit=1)[0] if args else ""
    if isinstance(args, (list, tuple)):
        if not args:
            return None
        return str(args[0])
    return str(args)


def _serialize_capability(capability: Any) -> Any:
    if isinstance(capability, (list, tuple, set, frozenset)):
        return [_serialize_capability(item) for item in capability]
    if isinstance(capability, FilesystemCapability):
        return {
            _CAPABILITY_MARKER: "filesystem",
            "roots": [str(root) for root in capability.roots],
        }
    if isinstance(capability, NetworkCapability):
        return {
            _CAPABILITY_MARKER: "network",
            "destinations": sorted(capability.destinations),
        }
    if isinstance(capability, SecretCapability):
        return {
            _CAPABILITY_MARKER: "secrets",
            "values": {
                key: value.hex() for key, value in sorted(capability.values.items())
            },
        }
    if isinstance(capability, SubprocessCapability):
        return {
            _CAPABILITY_MARKER: "subprocess",
            "allowed_commands": sorted(capability.allowed_commands),
            "allow_shell": capability.allow_shell,
        }
    if isinstance(capability, ReadPath):
        return {_CAPABILITY_MARKER: "read_path", "path": str(capability.path)}
    if isinstance(capability, WritePath):
        return {_CAPABILITY_MARKER: "write_path", "path": str(capability.path)}
    if isinstance(capability, ConnectTCP):
        return {
            _CAPABILITY_MARKER: "connect_tcp",
            "host": capability.host,
            "port": capability.port,
        }
    if isinstance(capability, Import):
        return {_CAPABILITY_MARKER: "import", "module": capability.module}
    if isinstance(capability, CpuBudget):
        return {_CAPABILITY_MARKER: "cpu_budget", "ms": capability.ms}
    if isinstance(capability, ClockCapability):
        return {_CAPABILITY_MARKER: "clock"}
    if isinstance(capability, RandomCapability):
        return {_CAPABILITY_MARKER: "random"}
    return capability


def _deserialize_capability(capability: Any) -> Any:
    if isinstance(capability, list):
        return [_deserialize_capability(item) for item in capability]
    if not isinstance(capability, dict):
        return capability
    kind = capability.get(_CAPABILITY_MARKER)
    if kind == "filesystem":
        roots = capability.get("roots", [])
        return FilesystemCapability.from_paths(*roots)
    if kind == "network":
        destinations = capability.get("destinations", [])
        return NetworkCapability.from_destinations(*destinations)
    if kind == "secrets":
        encoded_values = capability.get("values", {})
        decoded_values = {
            key: bytes.fromhex(value) for key, value in encoded_values.items()
        }
        return SecretCapability(values=decoded_values)
    if kind == "subprocess":
        commands = capability.get("allowed_commands", [])
        allow_shell = bool(capability.get("allow_shell", False))
        return SubprocessCapability.from_commands(*commands, allow_shell=allow_shell)
    if kind == "read_path":
        return ReadPath(capability["path"])
    if kind == "write_path":
        return WritePath(capability["path"])
    if kind == "connect_tcp":
        return ConnectTCP(str(capability["host"]), int(capability["port"]))
    if kind == "import":
        return Import(str(capability["module"]))
    if kind == "cpu_budget":
        return CpuBudget(int(capability["ms"]))
    if kind == "clock":
        return ClockCapability()
    if kind == "random":
        return RandomCapability()
    return capability


def serialize_capabilities(capabilities: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not capabilities:
        return {}
    return {
        name: _serialize_capability(capability)
        for name, capability in sorted(capabilities.items())
    }


def deserialize_capabilities(capabilities: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not capabilities:
        return {}
    if not isinstance(capabilities, dict):
        return {"authority": capabilities}
    return {
        name: _deserialize_capability(capability)
        for name, capability in capabilities.items()
    }


def _open_flags_from_mode(mode: object) -> int:
    """Translate Python open() modes to os.open() flags for brokered opens."""
    text = str(mode or "r")
    if "w" in text:
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    elif "a" in text:
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    elif "x" in text:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    else:
        flags = os.O_RDONLY
    if "+" in text:
        flags &= ~(os.O_RDONLY | os.O_WRONLY)
        flags |= os.O_RDWR
    return flags


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _safe_brokered_open(
    file,
    mode="r",
    buffering=-1,
    encoding=None,
    errors=None,
    newline=None,
    closefd=True,
    opener=None,
    *,
    allowed_roots: Iterable[Path],
):
    """Open *file* through a descriptor-relative sandbox broker.

    On platforms with ``dir_fd`` support, parent directories are traversed from
    an allowed root by file descriptor and every traversed component is opened
    with ``O_NOFOLLOW`` where available.  The final component is opened with
    ``os.open(..., dir_fd=parent_fd)`` and ``O_NOFOLLOW`` where available, then
    re-checked with ``fstat`` against a descriptor-relative ``stat`` of the same
    path.

    Compatibility fallback is intentionally explicit: if the platform lacks the
    required descriptor-relative primitives, access falls back to the previous
    resolved-path check before calling the original ``open``.  That fallback
    preserves portability but cannot provide the same symlink race protection.
    """
    if opener is not None:
        raise ValueError("custom openers are not supported in sandboxed open")
    if not closefd:
        raise ValueError("closefd=False is not supported in sandboxed open")

    policy_errors = sys.modules[__package__.rsplit(".", 1)[0] + ".errors"]
    roots = tuple(Path(root).resolve(strict=False) for root in allowed_roots)
    raw_path = Path(os.fsdecode(file) if isinstance(file, bytes) else os.fspath(file))
    lexical_path = Path(os.path.abspath(raw_path))
    root = next(
        (
            candidate
            for candidate in roots
            if lexical_path == candidate or lexical_path.is_relative_to(candidate)
        ),
        None,
    )
    if root is None:
        raise policy_errors.PolicyError("file access blocked")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    have_dir_fd = _ORIG_OS_OPEN in getattr(
        os, "supports_dir_fd", set()
    ) and os.stat in getattr(os, "supports_dir_fd", set())
    have_follow = os.stat in getattr(os, "supports_follow_symlinks", set())
    if nofollow and have_dir_fd and have_follow:
        root_fd = os.open(root, dir_flags)
        current_fd = root_fd
        fds = [root_fd]
        fd = -1
        try:
            rel_parts = lexical_path.relative_to(root).parts
            for part in rel_parts[:-1]:
                if part in ("", ".", ".."):
                    raise policy_errors.PolicyError("file access blocked")
                next_fd = os.open(part, dir_flags, dir_fd=current_fd)
                fds.append(next_fd)
                current_fd = next_fd
            final = rel_parts[-1] if rel_parts else "."
            flags = _open_flags_from_mode(mode) | nofollow
            fd = os.open(final, flags, 0o666, dir_fd=current_fd)
            opened_stat = os.fstat(fd)
            checked_stat = os.stat(final, dir_fd=current_fd, follow_symlinks=False)
            if not _same_file(opened_stat, checked_stat):
                os.close(fd)
                fd = -1
                raise policy_errors.PolicyError("file access blocked")
            return _ORIG_OPEN(
                fd, mode, buffering, encoding, errors, newline, closefd=True
            )
        except OSError as exc:
            if fd >= 0:
                os.close(fd)
            raise policy_errors.PolicyError("file access blocked") from exc
        finally:
            for descriptor in reversed(fds):
                os.close(descriptor)

    resolved = raw_path.resolve(strict=False)
    if not any(
        resolved == candidate or resolved.is_relative_to(candidate)
        for candidate in roots
    ):
        raise policy_errors.PolicyError("file access blocked")
    opened = _ORIG_OPEN(
        file, mode, buffering, encoding, errors, newline, closefd=closefd
    )
    try:
        final_stat = os.fstat(opened.fileno())
        resolved_stat = os.stat(resolved)
        if not _same_file(final_stat, resolved_stat):
            opened.close()
            raise policy_errors.PolicyError("file access blocked")
    except Exception:
        opened.close()
        raise
    return opened


def _iter_authorities(policy, capabilities: Optional[dict[str, Any]]) -> list[object]:
    authorities: list[object] = []
    if policy is not None:
        authorities.extend(getattr(policy, "capabilities", []) or [])
        if isinstance(policy, RuntimePolicy):
            return authorities
        for path in getattr(policy, "fs", []) or []:
            authorities.extend([ReadPath(path), WritePath(path)])
        for addr in getattr(policy, "tcp", []) or []:
            try:
                authorities.append(ConnectTCP.from_address(addr))
            except ValueError:
                pass
        for module in getattr(policy, "imports", []) or []:
            authorities.append(Import(module))
    if capabilities:
        values = (
            capabilities.values() if isinstance(capabilities, dict) else capabilities
        )
        for capability in values:
            if isinstance(capability, (list, tuple, set, frozenset)):
                authorities.extend(capability)
            else:
                authorities.append(capability)
    return authorities


def _fs_rule_matches(pattern: str, path: Path) -> bool:
    path_text = str(path)
    if pattern.endswith("/**"):
        root = Path(pattern[:-3]).resolve(strict=False)
        return path == root or path.is_relative_to(root)
    if any(char in pattern for char in "*?["):
        return fnmatch.fnmatch(path_text, pattern)
    return path == Path(pattern).resolve(strict=False) or path.is_relative_to(
        Path(pattern).resolve(strict=False)
    )


def _fs_rule_safe_root(pattern: str) -> Path | None:
    """Return the descriptor-broker root for a filesystem rule, if representable."""
    if pattern.endswith("/**"):
        root_pattern = pattern[:-3]
        if any(char in root_pattern for char in "*?["):
            return None
        return Path(root_pattern).resolve(strict=False)
    if any(char in pattern for char in "*?["):
        return None
    return Path(pattern).resolve(strict=False)


def _blocked_open(file, *args, **kwargs):
    """Restrict file access based on the current thread's policy."""

    if isinstance(file, os.PathLike):
        file = os.fspath(file)

    mode = args[0] if args else kwargs.get("mode", "r")
    text_mode = str(mode)
    wants_write = any(flag in text_mode for flag in ("w", "a", "x", "+"))
    safe_roots: tuple[Path, ...] | None = None

    if isinstance(file, (str, bytes)):
        display_path = Path(os.fsdecode(file) if isinstance(file, bytes) else file)
        lexical_path = Path(os.path.abspath(display_path))
        path = display_path.resolve(strict=False)

        authority = getattr(_thread_local, "authority", None)
        fs_cap = getattr(_thread_local, "fs_capability", None)
        allowed = getattr(_thread_local, "fs", None)
        runtime_policy = getattr(_thread_local, "runtime_policy", None)
        if fs_cap is not None:
            safe_roots = fs_cap.roots
            if not any(
                lexical_path == root or lexical_path.is_relative_to(root)
                for root in fs_cap.roots
            ):
                if not fs_cap.allows(path):
                    raise _deny(
                        "filesystem",
                        f"open:{path}",
                        f"capability:filesystem roots={_format_roots(fs_cap.roots)}",
                        "file access blocked",
                    )
        elif allowed is not None:
            safe_roots = tuple(allowed)
            if not any(
                lexical_path == a or lexical_path.is_relative_to(a) for a in allowed
            ):
                raise _deny(
                    "filesystem",
                    f"open:{path}",
                    f"allow_fs:{_format_roots(allowed)}",
                    "file access blocked",
                )
        elif authority is not None:
            candidate_roots = (
                authority.write_paths if wants_write else authority.read_paths
            )
            if candidate_roots:
                safe_roots = tuple(candidate_roots)
            else:
                raise errors.PolicyError("file access blocked")
            if wants_write:
                permitted = authority.allows_write(path)
            else:
                permitted = authority.allows_read(path)
            if not permitted:
                raise _deny(
                    "filesystem",
                    f"open:{path}",
                    "authority:write_path" if wants_write else "authority:read_path",
                    "file access blocked",
                )
        elif runtime_policy is not None:
            if any(
                _fs_rule_matches(rule.path, path) for rule in runtime_policy.deny_fs
            ):
                raise _deny(
                    "filesystem",
                    f"open:{path}",
                    "runtime_policy:deny_fs",
                    "file access blocked",
                )
            matching_allow_rules = [
                rule
                for rule in runtime_policy.allow_fs
                if _fs_rule_matches(rule.path, path)
                and rule.access
                in ({"write", "readwrite"} if wants_write else {"read", "readwrite"})
            ]
            if not matching_allow_rules:
                raise _deny(
                    "filesystem",
                    f"open:{path}",
                    "runtime_policy:allow_fs",
                    "file access blocked",
                )
            candidate_roots = tuple(
                _fs_rule_safe_root(rule.path) for rule in matching_allow_rules
            )
            if any(root is None for root in candidate_roots):
                raise _deny(
                    "filesystem",
                    f"open:{path}",
                    "runtime_policy:allow_fs",
                    "filesystem glob allow rules are not supported for brokered open",
                )
            safe_roots = tuple(root for root in candidate_roots if root is not None)
        elif getattr(_thread_local, "active", False):
            raise _deny(
                "filesystem",
                f"open:{path}",
                "deny-by-default",
                "file access blocked",
            )

    sandbox = getattr(_thread_local, "sandbox", None)
    if sandbox is not None:
        sandbox._check_open_files_quota()
    if safe_roots is not None and isinstance(file, (str, bytes)):
        mode_arg = args[0] if args else kwargs.pop("mode", "r")
        rest = args[1:] if args else ()
        opened = _safe_brokered_open(
            file, mode_arg, *rest, allowed_roots=safe_roots, **kwargs
        )
    else:
        opened = _ORIG_OPEN(file, *args, **kwargs)
    if sandbox is None:
        return opened
    sandbox._open_files += 1
    released = False
    release_lock = threading.Lock()

    def _release():
        nonlocal released
        with release_lock:
            if released:
                return
            released = True
            sandbox._open_files = max(0, sandbox._open_files - 1)

    original_close = opened.close

    def _close_once(*close_args, **close_kwargs):
        try:
            return original_close(*close_args, **close_kwargs)
        finally:
            _release()

    opened.close = _close_once
    weakref.finalize(opened, _release)
    return opened


def _check_network_destination(address: Iterable[str]) -> None:
    authority = getattr(_thread_local, "authority", None)
    net_cap = getattr(_thread_local, "net_capability", None)
    allowed = getattr(_thread_local, "tcp", None)
    runtime_policy = getattr(_thread_local, "runtime_policy", None)
    if isinstance(address, tuple):
        host, port, *_ = address
    else:
        host, port = address
    destination = f"{host}:{port}"
    if net_cap is not None:
        if not net_cap.allows(str(host), int(port)):
            raise _deny(
                "network",
                f"connect:{destination}",
                f"capability:network destinations={','.join(sorted(net_cap.destinations))}",
                f"connect blocked: {destination}",
            )
    elif allowed is not None:
        if destination not in allowed:
            raise _deny(
                "network",
                f"connect:{destination}",
                f"allow_tcp:{','.join(sorted(allowed))}",
                f"connect blocked: {destination}",
            )
    elif authority is not None:
        if not authority.allows_tcp(str(host), int(port)):
            raise _deny(
                "network",
                f"connect:{destination}",
                "authority:connect_tcp",
                f"connect blocked: {destination}",
            )
    elif runtime_policy is not None:
        if any(rule.destination == destination for rule in runtime_policy.deny_tcp):
            raise _deny(
                "network",
                f"connect:{destination}",
                "runtime_policy:deny_tcp",
                f"connect blocked: {destination}",
            )
        if not any(
            rule.destination == destination for rule in runtime_policy.allow_tcp
        ):
            raise _deny(
                "network",
                f"connect:{destination}",
                "runtime_policy:allow_tcp",
                f"connect blocked: {destination}",
            )
    elif getattr(_thread_local, "active", False):
        raise _deny(
            "network",
            f"connect:{destination}",
            "deny-by-default",
            f"connect blocked: {destination}",
        )
    sandbox = getattr(_thread_local, "sandbox", None)
    if sandbox is not None:
        sandbox._network_ops += 1
        if (
            sandbox.network_ops_max is not None
            and sandbox._network_ops > sandbox.network_ops_max
        ):
            raise errors.NetworkExceeded()


def _guarded_connect(self_socket: socket.socket, address: Iterable[str]):
    _check_network_destination(address)
    return _ORIG_SOCKET_CONNECT(self_socket, address)


def _guarded_connect_ex(self_socket: socket.socket, address: Iterable[str]):
    _check_network_destination(address)
    return _ORIG_SOCKET_CONNECT_EX(self_socket, address)


def _guarded_sendto(self_socket: socket.socket, data, *args, **kwargs):
    if args and isinstance(args[-1], tuple):
        _check_network_destination(args[-1])
    elif "address" in kwargs:
        _check_network_destination(kwargs["address"])
    else:
        raise errors.PolicyError("socket sendto blocked")
    return _ORIG_SOCKET_SENDTO(self_socket, data, *args, **kwargs)


def _deny_side_effect_api(api_name: str):
    def _blocked(*args, **kwargs):
        raise errors.PolicyError(
            f"{api_name} is blocked in the Python sandbox wrapper; "
            "production enforcement must come from the BPF/cgroup broker path"
        )

    _blocked.__name__ = f"blocked_{api_name.replace('.', '_')}"
    return _blocked


def _blocked_subprocess_run(*args, **kwargs):
    cap = getattr(_thread_local, "subprocess_capability", None)
    attempted = args[0] if args else kwargs.get("args")
    command_name = _subprocess_command_name(attempted)
    action = (
        f"subprocess.run:{command_name}" if command_name else "subprocess.run:<empty>"
    )
    if cap is None:
        raise _deny(
            "subprocess", action, "deny-by-default", "subprocess access blocked"
        )
    if isinstance(attempted, str) and not cap.allow_shell:
        raise _deny(
            "subprocess",
            action,
            "capability:subprocess shell=false",
            "shell string commands are not permitted",
        )
    if command_name is None:
        raise ValueError("empty command")
    if command_name not in cap.allowed_commands:
        raise _deny(
            "subprocess",
            action,
            f"capability:subprocess allowed_commands={','.join(sorted(cap.allowed_commands))}",
            f"subprocess blocked: {command_name}",
        )
    return cap.run(*args, **kwargs)


def _guarded_urandom(n: int) -> bytes:
    cap = getattr(_thread_local, "random_capability", None)
    if cap is None:
        raise _deny(
            "random",
            f"random.bytes:{n}",
            "deny-by-default",
            "randomness access blocked",
        )
    return cap.bytes(n)


def _make_sandbox_thread_class(sandbox: "SandboxThread"):
    class SandboxedThread(threading.Thread):
        def start(self, *args, **kwargs):
            sandbox._check_child_work_quota()
            original_run = self.run

            def _run_with_accounting(*r_args, **r_kwargs):
                try:
                    return original_run(*r_args, **r_kwargs)
                finally:
                    sandbox._child_work = max(0, sandbox._child_work - 1)

            self.run = _run_with_accounting  # type: ignore[assignment]
            sandbox._child_work += 1
            try:
                return _ORIG_THREAD_START(self, *args, **kwargs)
            except Exception:
                sandbox._child_work = max(0, sandbox._child_work - 1)
                raise

    return SandboxedThread


def _wrap_module(name: str, module):
    """Return developer-ergonomic wrappers around risky modules.

    These Python wrappers fail fast for tests and local development. They are
    not a production sandbox boundary; production denial and brokering should
    be enforced by the supervisor's BPF/cgroup broker path.
    """

    base = name.split(".")[0]
    if base in _BLOCKED_MODULES:
        raise errors.PolicyError(f"import of {base!r} is not permitted")
    if base == "time":

        def _require_clock() -> ClockCapability:
            cap = getattr(_thread_local, "clock_capability", None)
            return cap

        def _time() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.time()

        def _monotonic() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.monotonic()

        def _perf_counter() -> float:
            cap = _require_clock()
            if cap is None:
                return 0.0
            return cap.monotonic()

        mod = types.ModuleType("time", module.__doc__)
        mod.__dict__.update({k: getattr(time, k) for k in dir(time)})
        mod.time = _time
        mod.monotonic = _monotonic
        mod.perf_counter = _perf_counter
        return mod
    if base == "io":
        mod = types.ModuleType("io", module.__doc__)
        mod.__dict__.update({k: getattr(io, k) for k in dir(io)})
        mod.open = _blocked_open
        return mod
    if base == "socket":
        mod = types.ModuleType("socket", module.__doc__)
        mod.__dict__.update({k: getattr(socket, k) for k in dir(socket)})

        class GuardedSocket(socket.socket):
            def __init__(self, family=-1, type=-1, proto=-1, fileno=None):
                sock_type = type if type != -1 else socket.SOCK_STREAM
                # Socket type may include flags such as SOCK_NONBLOCK; the low
                # nibble carries the base type on Linux. Do not treat regular
                # SOCK_STREAM as raw just because 1 & 3 is truthy.
                if int(sock_type) & 0xF == int(socket.SOCK_RAW):
                    raise errors.PolicyError("raw sockets are blocked")
                if hasattr(socket, "AF_PACKET") and family == socket.AF_PACKET:
                    raise errors.PolicyError("packet sockets are blocked")
                super().__init__(family, type, proto, fileno)

            connect = _guarded_connect
            connect_ex = _guarded_connect_ex
            sendto = _guarded_sendto

        def _create_connection(
            address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None
        ):
            sock = GuardedSocket(socket.AF_INET, socket.SOCK_STREAM)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address is not None:
                sock.bind(source_address)
            try:
                sock.connect(address)
                return sock
            except Exception:
                sock.close()
                raise

        mod.socket = GuardedSocket
        mod.create_connection = _create_connection
        mod.socketpair = _deny_side_effect_api("socket.socketpair")
        mod.fromfd = _deny_side_effect_api("socket.fromfd")
        if hasattr(socket, "create_server"):
            mod.create_server = _deny_side_effect_api("socket.create_server")
        return mod
    if base == "subprocess":
        mod = types.ModuleType("subprocess", module.__doc__)
        mod.__dict__.update({k: getattr(subprocess, k) for k in dir(subprocess)})
        mod.run = _blocked_subprocess_run
        for attr in (
            "Popen",
            "call",
            "check_call",
            "check_output",
            "getoutput",
            "getstatusoutput",
        ):
            if hasattr(mod, attr):
                setattr(mod, attr, _deny_side_effect_api(f"subprocess.{attr}"))
        return mod
    if base == "os":
        mod = types.ModuleType("os", module.__doc__)
        mod.__dict__.update({k: getattr(os, k) for k in dir(os)})
        mod.urandom = _guarded_urandom
        for attr in (
            "open",
            "system",
            "popen",
            "fork",
            "forkpty",
            "posix_spawn",
            "posix_spawnp",
            "startfile",
        ):
            if hasattr(mod, attr):
                setattr(mod, attr, _deny_side_effect_api(f"os.{attr}"))
        for attr in dir(os):
            if attr.startswith("exec") or attr.startswith("spawn"):
                setattr(mod, attr, _deny_side_effect_api(f"os.{attr}"))
        return mod
    if base == "secrets":
        mod = types.ModuleType("secrets", module.__doc__)
        mod.__dict__.update({k: getattr(pysecrets, k) for k in dir(pysecrets)})
        mod.token_bytes = _guarded_urandom
        return mod
    if base == "random":
        mod = types.ModuleType("random", module.__doc__)
        mod.__dict__.update({k: getattr(random, k) for k in dir(random)})
        mod.randbytes = _guarded_urandom
        return mod
    if base == "threading":
        sandbox = getattr(_thread_local, "sandbox", None)
        if sandbox is None:
            return module
        mod = types.ModuleType("threading", module.__doc__)
        mod.__dict__.update({k: getattr(threading, k) for k in dir(threading)})
        mod.Thread = _make_sandbox_thread_class(sandbox)
        return mod
    if base == "pathlib":
        mod = types.ModuleType("pathlib", module.__doc__)
        mod.__dict__.update({k: getattr(module, k) for k in dir(module)})

        class SandboxedPath(type(module.Path())):
            def open(
                self,
                mode="r",
                buffering=-1,
                encoding=None,
                errors=None,
                newline=None,
            ):
                if "b" not in mode:
                    encoding = io.text_encoding(encoding)
                return _blocked_open(self, mode, buffering, encoding, errors, newline)

        mod.Path = SandboxedPath
        return mod
    return module


def _sandbox_import(name, globals=None, locals=None, fromlist=(), level=0):
    module = builtins.__import__(name, globals, locals, fromlist, level)
    return _wrap_module(name, module)


def _make_importer(allowed: Iterable[str]):
    allowed_set = {name.split(".")[0] for name in allowed}

    def _import(name, globals=None, locals=None, fromlist=(), level=0):
        base = name.split(".")[0]
        if base not in allowed_set:
            raise _deny(
                "import",
                f"import:{name}",
                f"allow_import:{','.join(sorted(allowed_set))}",
                f"import of {name!r} is not permitted",
            )
        module = builtins.__import__(name, globals, locals, fromlist, level)
        return _wrap_module(name, module)

    return _import


# Precompute a sanitized builtins dict for sandbox execution.
_FORBIDDEN = {
    "eval",
    "exec",
    "compile",
    "getattr",
    "setattr",
    "delattr",
}
_SAFE_BUILTINS = {
    name: getattr(builtins, name)
    for name in dir(builtins)
    if not name.startswith("_") or name == "__import__"
}
for name in _FORBIDDEN:
    _SAFE_BUILTINS.pop(name, None)
_SAFE_BUILTINS["open"] = _blocked_open
_SAFE_BUILTINS["__import__"] = _sandbox_import


def _sigxcpu_handler(signum, frame):
    raise errors.CPUExceeded()


_STOP = object()


class _KillRequest(Exception):
    """Internal exception used for asynchronous forced thread shutdown."""


@dataclass
class Stats:
    cpu_ms: float
    mem_bytes: int
    latency: dict[str, int]
    latency_sum: float
    errors: int
    operations: int
    cost: float
    denials: list[DenialEvent] = field(default_factory=list)


class SandboxThread(threading.Thread):
    """Thread that runs guest code and communicates via a queue."""

    @staticmethod
    def _merge_allowed_imports(policy, allowed_imports: Optional[Iterable[str]]):
        imports: set[str] = set()
        if policy is not None and getattr(policy, "imports", None):
            imports.update(policy.imports)
        if policy is not None:
            imports.update(
                AuthoritySet.from_authorities(
                    getattr(policy, "capabilities", []) or []
                ).imports
            )
        runtime_policy = from_sandbox_policy(policy) if policy is not None else None
        if runtime_policy is not None and runtime_policy.imports:
            imports.update(runtime_policy.imports)

        allowed_imports_provided = allowed_imports is not None
        if allowed_imports_provided:
            imports.update(allowed_imports)

        if not imports and not allowed_imports_provided:
            imports.update(DEFAULT_ALLOWED_IMPORTS)
        return imports

    def _init_config_wiring(
        self,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        network_ops_max: Optional[int] = None,
        output_bytes_max: Optional[int] = None,
        child_work_max: Optional[int] = None,
        allowed_imports: Optional[Iterable[str]] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
        capabilities: Optional[dict[str, Any]] = None,
        enforcement_status: Any = None,
    ) -> None:
        self.policy = policy
        self._authority = AuthoritySet.from_authorities(
            _iter_authorities(policy, capabilities)
        )
        self.cpu_quota_ms = cpu_ms if cpu_ms is not None else self._authority.cpu_ms
        self.runtime_policy = (
            from_sandbox_policy(policy) if policy is not None else None
        )
        self.mem_quota_bytes = mem_bytes
        self.wall_time_ms = wall_time_ms
        self.open_files_max = open_files_max
        self.network_ops_max = network_ops_max
        self.output_bytes_max = output_bytes_max
        self.child_work_max = child_work_max
        self.allowed_imports = self._merge_allowed_imports(policy, allowed_imports)
        self.numa_node = numa_node
        self._bound_numa_node = None
        self._cgroup_path = cgroup_path
        self.quota_enforcement = enforcement_status
        self._capabilities = deserialize_capabilities(capabilities)
        self._add_broker_ergonomic_imports()

    def _add_broker_ergonomic_imports(self) -> None:
        """Allow modules that are only useful with an explicit broker surface.

        The baseline default remains empty. These additions are tied to
        explicit policy/capability grants so examples can use the brokered
        Python modules without weakening the fail-closed import default.
        """

        if self.policy is not None and getattr(self.policy, "tcp", None):
            self.allowed_imports.add("socket")
        if "network" in self._capabilities:
            self.allowed_imports.add("socket")
        if "subprocess" in self._capabilities:
            self.allowed_imports.add("subprocess")
        if "random" in self._capabilities:
            self.allowed_imports.update({"os", "random", "secrets"})
        if "clock" in self._capabilities:
            self.allowed_imports.add("time")

    def _reset_runtime_state(self) -> None:
        self._cpu_time = 0.0
        self._mem_peak = 0
        self._mem_base = 0
        self._start_time = None
        self._ops = 0
        self._errors = 0
        self._latency = {"0.5": 0, "1": 0, "5": 0, "10": 0, "inf": 0}
        self._latency_sum = 0.0
        self._trace_enabled = False
        self._syscall_log: list[str] = []
        self._quarantine_reason = None
        self.termination_reason = None
        self._open_files = 0
        self._network_ops = 0
        self._output_bytes = 0
        self._child_work = 0
        self._denial_events: list[DenialEvent] = []

    def __init__(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        network_ops_max: Optional[int] = None,
        output_bytes_max: Optional[int] = None,
        child_work_max: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        on_violation: Optional[Callable[[str, Exception], None]] = None,
        tracer: Optional["Tracer"] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
        capabilities: Optional[dict[str, Any]] = None,
        enforcement_status: Any = None,
    ):
        super().__init__(name=name, daemon=True)
        self._logger = logging.getLogger(f"pyisolate.{name}")
        self._inbox: "queue.Queue[Any]" = queue.Queue()
        self._outbox: "queue.Queue[Any]" = queue.Queue()
        self._stop_event = threading.Event()
        self._on_violation = on_violation
        self._tracer = tracer or Tracer()
        self._init_config_wiring(
            policy=policy,
            cpu_ms=cpu_ms,
            mem_bytes=mem_bytes,
            wall_time_ms=wall_time_ms,
            open_files_max=open_files_max,
            network_ops_max=network_ops_max,
            output_bytes_max=output_bytes_max,
            child_work_max=child_work_max,
            allowed_imports=allowed_imports,
            numa_node=numa_node,
            cgroup_path=cgroup_path,
            capabilities=capabilities,
            enforcement_status=enforcement_status,
        )
        self._reset_runtime_state()
        self._tenant: str | None = None
        self._tenant_quota: int | None = None
        self._tenant_quota_reserved = False
        # Dedup set spans sandbox lifetimes for this thread; message IDs are monotonic
        # and intentionally preserved across reset() to avoid stale replay collisions.
        self._next_attach_msg_id = 1
        self._seen_attach_msg_ids: set[int] = set()

    def snapshot(self) -> dict:
        """Return serializable configuration state."""
        return {
            "name": self.name,
            "policy": self.policy,
            "cpu_ms": self.cpu_quota_ms,
            "mem_bytes": self.mem_quota_bytes,
            "allowed_imports": (
                sorted(self.allowed_imports)
                if self.allowed_imports is not None
                else None
            ),
            "numa_node": self.numa_node,
            "capabilities": serialize_capabilities(self._capabilities),
            "wall_time_ms": self.wall_time_ms,
            "open_files_max": self.open_files_max,
            "network_ops_max": self.network_ops_max,
            "output_bytes_max": self.output_bytes_max,
            "child_work_max": self.child_work_max,
        }

    def reset_config(self) -> dict[str, Any]:
        """Return the runtime options consumed by ``reset`` for reconfiguration."""
        return {
            "policy": self.policy,
            "cpu_ms": self.cpu_quota_ms,
            "mem_bytes": self.mem_quota_bytes,
            "wall_time_ms": self.wall_time_ms,
            "open_files_max": self.open_files_max,
            "network_ops_max": self.network_ops_max,
            "output_bytes_max": self.output_bytes_max,
            "child_work_max": self.child_work_max,
            "allowed_imports": (
                sorted(self.allowed_imports)
                if self.allowed_imports is not None
                else None
            ),
            "numa_node": self.numa_node,
            "capabilities": serialize_capabilities(self._capabilities),
        }

    def apply_reset_config(self, config: dict[str, Any]) -> None:
        """Apply a serialized runtime config produced by ``reset_config``."""
        self.policy = config.get("policy")
        self.cpu_quota_ms = config.get("cpu_ms")
        self.mem_quota_bytes = config.get("mem_bytes")
        self.wall_time_ms = config.get("wall_time_ms")
        self.open_files_max = config.get("open_files_max")
        self.network_ops_max = config.get("network_ops_max")
        self.output_bytes_max = config.get("output_bytes_max")
        self.child_work_max = config.get("child_work_max")
        self.numa_node = config.get("numa_node")
        self.allowed_imports = self._merge_allowed_imports(
            self.policy, config.get("allowed_imports")
        )
        self._capabilities = deserialize_capabilities(config.get("capabilities"))

    @staticmethod
    def _estimate_output_size(item: Any) -> int:
        if isinstance(item, bytes):
            return len(item)
        if isinstance(item, str):
            return len(item.encode("utf-8"))
        return len(repr(item).encode("utf-8"))

    def _post(self, item: Any) -> None:
        self._emit(item)

    def _emit(self, item: Any) -> None:
        self._output_bytes += self._estimate_output_size(item)
        if (
            self.output_bytes_max is not None
            and self._output_bytes > self.output_bytes_max
        ):
            raise errors.OutputExceeded()
        self._outbox.put(item)

    def _log(self, level: str, message: str, **fields: Any) -> None:
        self._emit(LogEvent(level=level, message=message, fields=fields))

    def _metric(
        self, name: str, value: int | float, tags: Optional[dict[str, str]] = None
    ) -> None:
        self._emit(MetricEvent(name=name, value=value, tags=tags or {}))

    def _request(
        self, capability: str, action: str, payload: Optional[dict[str, Any]] = None
    ) -> None:
        if capability not in self._capabilities:
            raise errors.PolicyError(f"capability request blocked: {capability}")
        self._emit(
            BrokerRequest(
                capability=capability,
                action=action,
                payload=payload or {},
            )
        )

    def _check_open_files_quota(self) -> None:
        if self.open_files_max is not None and self._open_files >= self.open_files_max:
            raise errors.OpenFilesExceeded()

    def _check_child_work_quota(self) -> None:
        if self.child_work_max is not None and self._child_work >= self.child_work_max:
            raise errors.ChildWorkExceeded()

    def _trace_guard(self, frame, event, arg):
        if self.wall_time_ms is None:
            return self._trace_guard
        if self._start_time is None:
            return self._trace_guard
        elapsed_ms = (time.monotonic() - self._start_time) * 1000
        if elapsed_ms > self.wall_time_ms:
            raise errors.WallTimeExceeded()
        return self._trace_guard

    def _record_denial(self, event: DenialEvent) -> None:
        self._denial_events.append(event)
        self._logger.warning(
            "operation denied", extra={"denial_event": event.to_dict()}
        )

    def get_denial_events(self) -> list[dict[str, str]]:
        """Return structured denial telemetry for this sandbox."""
        return [event.to_dict() for event in self._denial_events]

    def enable_tracing(self) -> None:
        """Start recording guest operations."""
        self._trace_enabled = True
        self._syscall_log = []

    def get_syscall_log(self) -> list[str]:
        """Return recorded guest operations."""
        return list(self._syscall_log)

    def profile(self) -> Stats:
        """Return current CPU and memory usage."""
        return self.stats

    def exec(self, src: str) -> None:
        if self._trace_enabled:
            self._syscall_log.append(src)
        self._logger.debug("exec", extra={"code": src})
        self._inbox.put(ExecRequest(source=src))

    def call(self, func: str, *args, timeout: float | None = None, **kwargs) -> Any:
        if self._trace_enabled:
            self._syscall_log.append(f"call {func}")
        self._logger.debug("call", extra={"func": func})
        self._inbox.put(CallRequest(target=func, args=args, kwargs=kwargs))
        try:
            result = self.recv(timeout)
        except Exception as exc:  # sandbox raised
            if isinstance(exc, errors.SandboxError):
                raise exc
            raise errors.SandboxError(str(exc)) from exc
        return result

    def recv(self, timeout: Optional[float] = None):
        try:
            result = self._outbox.get(timeout=timeout)
            if isinstance(result, Exception):
                raise result
            return result
        except queue.Empty:
            raise errors.TimeoutError("no message received")

    def cancel(self, timeout: float = 0.2) -> bool:
        """Request cooperative shutdown and wait up to *timeout* seconds."""
        self._stop_event.set()
        self._inbox.put(StopRequest())
        self.join(timeout)
        return not self.is_alive()

    def kill(self, timeout: float = 0.2) -> bool:
        """Attempt non-cooperative termination for wedged guest code."""
        if self.cancel(timeout=timeout):
            return True
        if self.ident is None:
            return not self.is_alive()
        for _ in range(3):
            result = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(self.ident), ctypes.py_object(_KillRequest)
            )
            if result > 1:
                ctypes.pythonapi.PyThreadState_SetAsyncExc(
                    ctypes.c_ulong(self.ident), None
                )
            self.join(timeout / 3 if timeout > 0 else 0)
            if not self.is_alive():
                return True
        return False

    def stop(self, timeout: float = 0.2) -> None:
        if not self.cancel(timeout=timeout):
            self.kill(timeout=timeout)

    def enforce_quota_breach(
        self, exc: Exception, reason: str, timeout: float = 0.05
    ) -> bool:
        """Record a kernel/watchdog quota breach and stop guest execution.

        The watchdog calls this path from outside the sandbox thread, so it does
        not depend on guest bytecode returning to Python-level quota checks.
        If asynchronous termination cannot stop the thread promptly, the sandbox
        is marked quarantined for supervisor cleanup.
        """

        self.termination_reason = reason
        stopped = self.kill(timeout=timeout)
        if not stopped:
            self.quarantine(reason)
        self._outbox.put(exc)
        return stopped

    def reap(self) -> bool:
        """Drain pending messages after termination."""
        if self.is_alive():
            return False
        while not self._inbox.empty():
            try:
                self._inbox.get_nowait()
            except queue.Empty:
                break
        while not self._outbox.empty():
            try:
                self._outbox.get_nowait()
            except queue.Empty:
                break
        return True

    def quarantine(self, reason: str) -> None:
        self._quarantine_reason = reason

    def reset(
        self,
        name: str,
        policy=None,
        cpu_ms: Optional[int] = None,
        mem_bytes: Optional[int] = None,
        wall_time_ms: Optional[int] = None,
        open_files_max: Optional[int] = None,
        network_ops_max: Optional[int] = None,
        output_bytes_max: Optional[int] = None,
        child_work_max: Optional[int] = None,
        allowed_imports: Optional[list[str]] = None,
        numa_node: Optional[int] = None,
        cgroup_path=None,
        capabilities: Optional[dict[str, Any]] = None,
        enforcement_status: Any = None,
    ) -> None:
        """Reuse this thread for a new sandbox."""
        old_path = getattr(self, "_cgroup_path", None)
        self.name = name
        self._init_config_wiring(
            policy=policy,
            cpu_ms=cpu_ms,
            mem_bytes=mem_bytes,
            wall_time_ms=wall_time_ms,
            open_files_max=open_files_max,
            network_ops_max=network_ops_max,
            output_bytes_max=output_bytes_max,
            child_work_max=child_work_max,
            allowed_imports=allowed_imports,
            numa_node=numa_node,
            cgroup_path=cgroup_path,
            capabilities=capabilities,
            enforcement_status=enforcement_status,
        )
        self._reset_runtime_state()
        # Request the sandbox thread to (re)attach itself to the new cgroup.
        # The attachment must happen from the sandbox thread's context.
        msg_id = self._next_attach_msg_id
        self._next_attach_msg_id += 1
        self._inbox.put(AttachCgroupRequest(old_path=old_path, msg_id=msg_id))

    @property
    def stats(self):
        cpu_ms = self._cpu_time
        if self._start_time is not None:
            cpu_ms += (time.monotonic() - self._start_time) * 1000
        cost = cpu_ms * 0.0001 + self._mem_peak * 1e-9
        return Stats(
            cpu_ms=cpu_ms,
            mem_bytes=self._mem_peak,
            latency=dict(self._latency),
            latency_sum=self._latency_sum,
            errors=self._errors,
            operations=self._ops,
            cost=cost,
            denials=list(self._denial_events),
        )

    # internal thread run loop
    def run(self) -> None:
        try:
            prev_handler = signal.signal(signal.SIGXCPU, _sigxcpu_handler)
        except ValueError:
            prev_handler = None

        try:
            _thread_local.active = True

            if not tracemalloc.is_tracing():
                tracemalloc.start()
            try:
                from .. import cgroup

                cgroup.attach_current(self._cgroup_path)
            except Exception:
                pass
            self._mem_base = tracemalloc.get_traced_memory()[0]
            self._cpu_time = 0.0
            self._start_time = None

            local_vars = {
                "post": self._post,
                "log": self._log,
                "metric": self._metric,
                "request": self._request,
                "caps": self._capabilities,
            }

            if self.numa_node is not None:
                bind_current_thread(self.numa_node)
            self._bound_numa_node = self.numa_node

            while True:
                payload = self._inbox.get()
                if payload is _STOP:
                    break
                if isinstance(payload, StopRequest):
                    break
                if isinstance(payload, AttachCgroupRequest):
                    if payload.msg_id in self._seen_attach_msg_ids:
                        continue
                    self._seen_attach_msg_ids.add(payload.msg_id)
                    try:
                        from .. import cgroup

                        cgroup.attach_current(self._cgroup_path)
                        if payload.old_path and payload.old_path != self._cgroup_path:
                            cgroup.delete(payload.old_path)
                    except Exception:
                        pass
                    continue

                if self.numa_node != self._bound_numa_node:
                    if self.numa_node is not None:
                        bind_current_thread(self.numa_node)
                    self._bound_numa_node = self.numa_node
                if isinstance(payload, str):
                    payload = ExecRequest(source=payload)

                allowed_tcp = None
                allowed_fs = None
                if self.policy is not None and not isinstance(
                    self.policy, RuntimePolicy
                ):
                    tcp_policy = getattr(self.policy, "tcp", None)
                    if tcp_policy:
                        allowed_tcp = set(tcp_policy)
                    if getattr(self.policy, "fs", None):
                        allowed_fs = [
                            Path(p).resolve(strict=False) for p in self.policy.fs
                        ]
                if allowed_tcp is None:
                    if hasattr(_thread_local, "tcp"):
                        delattr(_thread_local, "tcp")
                else:
                    _thread_local.tcp = allowed_tcp
                _thread_local.fs = allowed_fs
                _thread_local.authority = (
                    self._authority
                    if _iter_authorities(self.policy, self._capabilities)
                    else None
                )
                _thread_local.runtime_policy = self.runtime_policy
                _thread_local.fs_capability = self._capabilities.get("filesystem")
                _thread_local.net_capability = self._capabilities.get("network")
                _thread_local.subprocess_capability = self._capabilities.get(
                    "subprocess"
                )
                _thread_local.clock_capability = self._capabilities.get("clock")
                _thread_local.random_capability = self._capabilities.get("random")
                _thread_local.sandbox = self

                builtins_dict = _SAFE_BUILTINS.copy()
                builtins_dict["open"] = _blocked_open
                builtins_dict["__import__"] = _make_importer(self.allowed_imports)
                local_vars["__builtins__"] = builtins_dict

                self._ops += 1
                op_start = time.monotonic()
                with self._tracer.start_span(f"sandbox:{self.name}"):
                    sys_trace_before = sys.gettrace()
                    try:
                        start_cpu = time.thread_time()
                        self._start_time = time.monotonic()
                        sys.settrace(self._trace_guard)
                        if isinstance(payload, CallRequest):
                            importer = builtins_dict["__import__"]
                            try:
                                module_name, func_name = payload.target.rsplit(".", 1)
                            except ValueError as exc:
                                raise errors.SandboxError(
                                    "call target {!r} must include a module path (e.g. 'module.func')".format(
                                        payload.target
                                    )
                                ) from exc
                            mod = importer(module_name, fromlist=["_"])
                            res = object.__getattribute__(mod, func_name)(
                                *payload.args, **payload.kwargs
                            )
                            self._post(res)
                        elif isinstance(payload, ExecRequest):
                            exec(payload.source, local_vars, local_vars)
                        else:
                            raise errors.SandboxError("unknown request type")
                        end_cpu = time.thread_time()
                        self._cpu_time += (end_cpu - start_cpu) * 1000
                        self._start_time = None
                        cur, peak = tracemalloc.get_traced_memory()
                        self._mem_peak = max(self._mem_peak, peak - self._mem_base)
                        # CPU and RSS quotas are enforced by cgroups/eBPF and
                        # ResourceWatchdog.  tracemalloc remains debugging
                        # telemetry for Stats only; it is not a security limit.
                    except Exception as exc:  # real impl would sanitize
                        if isinstance(exc, _KillRequest):
                            break
                        self._errors += 1
                        self._start_time = None
                        if isinstance(exc, errors.WallTimeExceeded):
                            self.termination_reason = "wall_time_exceeded"
                        elif isinstance(exc, errors.OpenFilesExceeded):
                            self.termination_reason = "open_files_exceeded"
                        elif isinstance(exc, errors.NetworkExceeded):
                            self.termination_reason = "network_exceeded"
                        elif isinstance(exc, errors.OutputExceeded):
                            self.termination_reason = "output_exceeded"
                        elif isinstance(exc, errors.ChildWorkExceeded):
                            self.termination_reason = "child_work_exceeded"
                        elif isinstance(exc, errors.CPUExceeded):
                            self.termination_reason = "cpu_exceeded"
                        elif isinstance(exc, errors.MemoryExceeded):
                            self.termination_reason = "memory_exceeded"
                        if self._on_violation and isinstance(exc, errors.PolicyError):
                            self._on_violation(self.name, exc)
                        self._outbox.put(exc)
                    finally:
                        sys.settrace(sys_trace_before)
                        self._start_time = None
                        duration = (time.monotonic() - op_start) * 1000
                        self._latency_sum += duration
                        if duration <= 0.5:
                            self._latency["0.5"] += 1
                        elif duration <= 1:
                            self._latency["1"] += 1
                        elif duration <= 5:
                            self._latency["5"] += 1
                        elif duration <= 10:
                            self._latency["10"] += 1
                        else:
                            self._latency["inf"] += 1
            _thread_local.active = False
        finally:
            if prev_handler is not None:
                signal.signal(signal.SIGXCPU, prev_handler)
