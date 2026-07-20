"""eBPF loader and hot‑reloader.

This module compiles a very small eBPF program and attempts to attach it via
``bpftool``.  The build is intentionally simple and serves purely as a proof of
concept used by the tests.  ``bpftool`` and ``llvm-objdump`` may not be
available on the test system; any missing executables are therefore ignored.
"""

import hashlib
import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Literal

from platformdirs import user_cache_dir

from ..policy.compiler import PolicyCompilerError, compile_policy
from ..policy.model import from_compiled_policy, to_bpf_map_entries

logger = logging.getLogger(__name__)

# BPF hash maps require fixed-width keys and values. The logical entries from
# ``to_bpf_map_entries`` (e.g. ``"default:0"`` -> ``"/tmp/**"``) are therefore
# encoded to fixed-width little-endian byte strings before being handed to
# ``bpftool``, which consumes them as space-separated hex tokens. A blake2b
# digest gives a deterministic, collision-resistant fixed-width encoding for the
# variable-length logical strings; the matching kernel-side derivation is a
# separate concern from this user-space encoding.
BPF_KEY_BYTES = 8
BPF_VALUE_BYTES = 8


def encode_map_field(text: str, width: int) -> list[str]:
    """Encode *text* as *width* hex byte tokens (``["0x.."]``) for ``bpftool``."""
    digest = hashlib.blake2b(text.encode("utf-8"), digest_size=width).digest()
    return [f"0x{byte:02x}" for byte in digest]


class BPFManager:
    """Compile and manage a minimal eBPF program.

    Compilation and skeleton generation are cached per instance so that
    repeated loads can reuse the pre-built object.
    """

    _SKEL_CACHE: dict[Path, str] = {}
    _CACHE_ENV = "PYISOLATE_BPF_CACHE"

    @classmethod
    def _cache_dir(cls) -> Path:
        """Return the writable cache directory for generated BPF artifacts."""

        cache_root = os.environ.get(cls._CACHE_ENV)
        path = (
            Path(cache_root).expanduser()
            if cache_root
            else Path(user_cache_dir("pyisolate")) / "bpf"
        )
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise RuntimeError(
                f"Unable to create BPF cache directory {path!s}. "
                "Set PYISOLATE_BPF_CACHE to a writable directory before loading BPF programs; "
                f"hardened mode cannot continue without writable generated-artifact storage: {exc}"
            ) from exc
        if not path.is_dir():
            raise RuntimeError(
                f"BPF cache path {path!s} exists but is not a directory. "
                "Set PYISOLATE_BPF_CACHE to a writable directory."
            )
        return path

    def __init__(self):
        self.loaded = False
        self.policy_maps: dict[str, object] = {}
        self._src = Path(__file__).with_name("dummy.bpf.c")
        self._cache = self._cache_dir()
        self._obj = self._cache / "dummy.bpf.o"
        self._skel = self._cache / "dummy.skel.h"
        self.skeleton = ""
        self._compiled_skeleton = False
        self._filter_src = Path(__file__).with_name("syscall_filter.bpf.c")
        self._filter_obj = self._cache / "syscall_filter.bpf.o"
        self._guard_src = Path(__file__).with_name("resource_guard.bpf.c")
        self._guard_obj = self._cache / "resource_guard.bpf.o"
        self._bpffs_root = Path("/sys/fs/bpf/pyisolate")
        self._dummy_pin = Path("/sys/fs/bpf/dummy")
        self._filter_pin_dir = self._bpffs_root / "syscall_filter"
        self._guard_pin_dir = self._bpffs_root / "resource_guard"
        self._skel_cache = self._SKEL_CACHE

    # internal helper
    def _run(self, cmd: list[str], *, raise_on_error: bool = False) -> bool:
        """Run a subprocess command and report success.

        On failure the stderr of the command is logged.  When ``raise_on_error``
        is true a :class:`RuntimeError` including the command's stderr is raised
        so callers can surface a descriptive message to users.
        """

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except FileNotFoundError as exc:
            # Missing tools are expected in some environments; log and continue
            # in lenient mode so that sandboxing can still function without BPF
            # enforcement.
            logger.error("command not found while running %s: %s", cmd, cmd[0])
            if raise_on_error:
                raise RuntimeError(
                    f"Command not found: {cmd[0]} (full command: {' '.join(cmd)})"
                ) from exc
            return False
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            logger.error("command failed %s: %s", cmd, stderr.strip())
            if raise_on_error:
                raise RuntimeError(
                    f"Command '{cmd[0]}' failed with exit code {exc.returncode}: {stderr.strip()}"
                ) from exc
        return False

    def load(
        self,
        *,
        strict: bool | None = None,
        mode: Literal["dev", "hardened", "compatibility"] = "dev",
    ) -> None:
        """Compile and attempt to attach the eBPF programs.

        Rollout modes:

        * ``dev``: low-friction mode; tolerate missing tooling and keep running.
          Use only for local development because BPF enforcement can be absent.
        * ``hardened``: production default; any failure raises a ``RuntimeError``
          and leaves the manager unloaded so callers fail closed.
        * ``compatibility``: caller-acknowledged reduced enforcement for ecosystem
          testing. Loads the baseline program but skips stricter filter/guard
          attachments.

        The legacy ``strict`` argument is still honored. When provided it
        overrides ``mode``.
        """
        if strict is not None:
            mode = "hardened" if strict else "dev"
        elif mode not in {"dev", "hardened", "compatibility"}:
            raise ValueError(f"invalid rollout mode: {mode}")

        strict_mode = mode == "hardened"

        dummy_compile = [
            "clang",
            "-target",
            "bpf",
            "-O2",
            "-c",
            str(self._src),
            "-o",
            str(self._obj),
        ]
        filter_compile = [
            "clang",
            "-target",
            "bpf",
            "-O2",
            "-c",
            str(self._filter_src),
            "-o",
            str(self._filter_obj),
        ]
        guard_compile = [
            "clang",
            "-target",
            "bpf",
            "-O2",
            "-c",
            str(self._guard_src),
            "-o",
            str(self._guard_obj),
        ]
        ok = True
        compile_cmd = dummy_compile
        if self._src not in self._skel_cache or (
            self._skel_cache.get(self._src) == "" and not self._compiled_skeleton
        ):
            ok &= self._run(compile_cmd, raise_on_error=strict_mode)
            skel_cmd = [
                "sh",
                "-c",
                f"bpftool gen skeleton {shlex.quote(str(self._obj))} > {shlex.quote(str(self._skel))}",
            ]
            ok &= self._run(skel_cmd, raise_on_error=strict_mode)
            if ok and self._skel.exists():
                try:
                    self._skel_cache[self._src] = self._skel.read_text()
                except OSError:
                    self._skel_cache[self._src] = ""
            elif ok:
                # Cache a placeholder when the build path was exercised but no
                # skeleton was emitted (for example under a mocked bpftool).
                self._skel_cache.setdefault(self._src, "")
            self.skeleton = self._skel_cache.get(self._src, "")
            if ok:
                self._compiled_skeleton = True
        else:
            self.skeleton = self._skel_cache[self._src]

        ok &= self._run(
            ["llvm-objdump", "-d", str(self._obj)], raise_on_error=strict_mode
        )
        ok &= self._run(
            ["bpftool", "prog", "load", str(self._obj), str(self._dummy_pin)],
            raise_on_error=strict_mode,
        )
        if mode != "compatibility":
            ok &= self._run(filter_compile, raise_on_error=strict_mode)
            ok &= self._run(guard_compile, raise_on_error=strict_mode)
            ok &= self._run(
                ["llvm-objdump", "-d", str(self._filter_obj)],
                raise_on_error=strict_mode,
            )
            ok &= self._run(
                ["llvm-objdump", "-d", str(self._guard_obj)],
                raise_on_error=strict_mode,
            )
            ok &= self._run(
                [
                    "bpftool",
                    "prog",
                    "loadall",
                    str(self._filter_obj),
                    str(self._filter_pin_dir),
                    "type",
                    "lsm",
                    "pinmaps",
                    str(self._bpffs_root),
                    "autoattach",
                ],
                raise_on_error=strict_mode,
            )
            ok &= self._run(
                [
                    "bpftool",
                    "prog",
                    "loadall",
                    str(self._guard_obj),
                    str(self._guard_pin_dir),
                    "pinmaps",
                    str(self._bpffs_root),
                    "autoattach",
                ],
                raise_on_error=strict_mode,
            )
            ok &= self._attach_loaded_programs(raise_on_error=strict_mode)
        self.loaded = ok
        if strict_mode and not ok:
            raise RuntimeError("BPF load failed; see logs for details")

    def _attach_loaded_programs(self, *, raise_on_error: bool = False) -> bool:
        """Attach programs that cannot rely solely on pinned objects.

        ``bpftool prog loadall ... autoattach`` creates BPF links for LSM and
        tracepoint programs on modern kernels.  The explicit cgroup-skb attach is
        retained for kernels/tools that require a concrete cgroup attach point.
        """

        ok = True
        cgroup_root = Path("/sys/fs/cgroup")
        egress_prog = self._guard_pin_dir / "account_cgroup_egress"
        ok &= self._run(
            [
                "bpftool",
                "cgroup",
                "attach",
                str(cgroup_root),
                "egress",
                "pinned",
                str(egress_prog),
            ],
            raise_on_error=raise_on_error,
        )
        return ok

    def _load_runtime_policy_yaml(self, path: Path):
        try:
            return from_compiled_policy(compile_policy(path))
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise RuntimeError(f"Invalid policy data in {path}: {exc}") from exc

    def _load_runtime_policy_json(self, path: Path):
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise RuntimeError("Policy data must be a JSON object")
        try:
            return from_compiled_policy(data)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid policy data in {path}: {exc}") from exc

    def hot_reload(self, policy_path: str) -> None:
        """Refresh maps based on a policy file.

        ``.yml``/``.yaml`` files are treated as authoring templates and compiled
        through the policy compiler.  ``.json`` files keep the existing canonical
        runtime-policy path.  Unknown suffixes try YAML first so users get DSL
        validation errors before falling back to JSON parsing.
        """
        if not self.loaded:
            raise RuntimeError("BPF not loaded")

        path = Path(policy_path)
        suffix = path.suffix.lower()

        try:
            if suffix in {".yml", ".yaml"}:
                runtime_policy = self._load_runtime_policy_yaml(path)
            elif suffix == ".json":
                runtime_policy = self._load_runtime_policy_json(path)
            else:
                try:
                    runtime_policy = self._load_runtime_policy_yaml(path)
                except (OSError, RuntimeError) as yaml_exc:
                    try:
                        runtime_policy = self._load_runtime_policy_json(path)
                    except (RuntimeError, json.JSONDecodeError) as json_exc:
                        raise RuntimeError(
                            f"Invalid policy file {policy_path}: YAML error: {yaml_exc}; "
                            f"JSON error: {json_exc}"
                        ) from json_exc
        except FileNotFoundError as exc:
            raise RuntimeError(f"Policy file not found: {policy_path}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Invalid JSON in policy file {policy_path}: {exc}"
            ) from exc
        except (PolicyCompilerError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid policy data in {policy_path}: {exc}") from exc
        except OSError as exc:
            raise RuntimeError(
                f"Unable to read policy file {policy_path}: {exc}"
            ) from exc

        # Build the replacement policy first, but only publish it after every
        # kernel map update succeeds. This keeps userspace state aligned with the
        # last fully-applied BPF policy if a partial hot reload fails.
        new_policy_maps = runtime_policy.to_dict()
        attempted_updates: list[tuple[str, str, str]] = []
        previous_entries: dict[tuple[str, str], str] = {}
        if self.policy_maps:
            try:
                previous_entries = {
                    (map_name, key): value
                    for map_name, key, value in to_bpf_map_entries(
                        from_compiled_policy(self.policy_maps)
                    )
                }
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "unable to build rollback entries from current policy maps: %s",
                    exc,
                )

        for map_name, key, value in to_bpf_map_entries(runtime_policy):
            logger.info("updating map %s[%s] -> %s", map_name, key, value)
            try:
                self._update_bpf_map(map_name, key, value)
            except RuntimeError as exc:
                rollback_errors = self._rollback_bpf_map_updates(
                    attempted_updates, previous_entries
                )
                rollback_context = ""
                if rollback_errors:
                    rollback_context = (
                        f"; rollback errors: {'; '.join(rollback_errors)}"
                    )
                raise RuntimeError(
                    f"BPF map update failed for {map_name}[{key}] with value {value!r} "
                    f"after {len(attempted_updates)} successful update(s): {exc}"
                    f"{rollback_context}"
                ) from exc
            attempted_updates.append((map_name, key, value))

        # Replace the active policy entirely to drop removed entries. Store the
        # canonical structure, not the source JSON shape, so the userspace and BPF
        # paths have one representation.
        self.policy_maps = new_policy_maps

    def set_sandbox_policy(
        self,
        cgroup_id: int,
        deny_mask: int,
        *,
        audit_only: bool = False,
        strict: bool = False,
    ) -> bool:
        """Write one sandbox's coarse deny-mask into the pinned ``sandbox_policy``
        map, keyed by its cgroup id, so the LSM program enforces it.

        Returns whether the update succeeded. When ``strict`` is set (hardened
        rollout), a failure raises instead of being reported as ``False``.
        """
        from .contract import (
            SANDBOX_POLICY_MAP,
            encode_sandbox_policy_key,
            encode_sandbox_policy_value,
        )

        pinned = self._bpffs_root / SANDBOX_POLICY_MAP
        return self._run(
            [
                "bpftool",
                "map",
                "update",
                "pinned",
                str(pinned),
                "key",
                *encode_sandbox_policy_key(cgroup_id),
                "value",
                *encode_sandbox_policy_value(deny_mask, audit_only),
                "any",
            ],
            raise_on_error=strict,
        )

    def _update_bpf_map(self, map_name: str, key: str, value: str) -> None:
        self._run(
            [
                "bpftool",
                "map",
                "update",
                "pinned",
                f"/sys/fs/bpf/{map_name}",
                "key",
                *encode_map_field(key, BPF_KEY_BYTES),
                "value",
                *encode_map_field(value, BPF_VALUE_BYTES),
                "any",
            ],
            raise_on_error=True,
        )

    def _rollback_bpf_map_updates(
        self,
        attempted_updates: list[tuple[str, str, str]],
        previous_entries: dict[tuple[str, str], str],
    ) -> list[str]:
        """Best-effort rollback for map entries changed during hot reload."""

        rollback_errors: list[str] = []
        for rollback_map, rollback_key, _ in reversed(attempted_updates):
            previous_value = previous_entries.get((rollback_map, rollback_key))
            if previous_value is None:
                logger.warning(
                    "no previous value available to rollback %s[%s]",
                    rollback_map,
                    rollback_key,
                )
                continue
            try:
                logger.info(
                    "rolling back map %s[%s] -> %s",
                    rollback_map,
                    rollback_key,
                    previous_value,
                )
                self._update_bpf_map(rollback_map, rollback_key, previous_value)
            except RuntimeError as rollback_exc:
                rollback_errors.append(
                    f"{rollback_map}[{rollback_key}] -> {previous_value!r}: {rollback_exc}"
                )
        return rollback_errors

    def open_ring_buffer(self):
        """Return an iterator over resource guard events."""
        return iter(())
