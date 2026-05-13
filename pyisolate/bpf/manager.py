"""eBPF loader and hot‑reloader.

This module compiles a very small eBPF program and attempts to attach it via
``bpftool``.  The build is intentionally simple and serves purely as a proof of
concept used by the tests.  ``bpftool`` and ``llvm-objdump`` may not be
available on the test system; any missing executables are therefore ignored.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Literal

from ..policy.model import from_compiled_policy, to_bpf_map_entries

logger = logging.getLogger(__name__)


class BPFManager:
    """Compile and manage a minimal eBPF program.

    Compilation and skeleton generation are cached per instance so that
    repeated loads can reuse the pre-built object.
    """

    _SKEL_CACHE: dict[Path, str] = {}

    def __init__(self):
        self.loaded = False
        self.policy_maps: dict[str, object] = {}
        self._src = Path(__file__).with_name("dummy.bpf.c")
        self._obj = Path(__file__).with_name("dummy.bpf.o")
        self._skel = Path(__file__).with_name("dummy.skel.h")
        self.skeleton = ""
        self._compiled_skeleton = False
        self._filter_src = Path(__file__).with_name("syscall_filter.bpf.c")
        self._filter_obj = Path(__file__).with_name("syscall_filter.bpf.o")
        self._guard_src = Path(__file__).with_name("resource_guard.bpf.c")
        self._guard_obj = Path(__file__).with_name("resource_guard.bpf.o")
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
                f"bpftool gen skeleton {self._obj} > {self._skel}",
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

    def hot_reload(self, policy_path: str) -> None:
        """Refresh maps based on a policy JSON file."""
        if not self.loaded:
            raise RuntimeError("BPF not loaded")
        try:
            with open(policy_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError as exc:
            raise RuntimeError(f"Policy file not found: {policy_path}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Invalid JSON in policy file {policy_path}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("Policy data must be a JSON object")
        try:
            runtime_policy = from_compiled_policy(data)
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"Invalid policy data in {policy_path}: {exc}") from exc

        # Replace the active policy entirely to drop removed entries. Store the
        # canonical structure, not the source JSON shape, so the userspace and BPF
        # paths have one representation.
        self.policy_maps = runtime_policy.to_dict()
        for map_name, key, value in to_bpf_map_entries(runtime_policy):
            logger.info("updating map %s[%s] -> %s", map_name, key, value)
            try:
                self._run(
                    [
                        "bpftool",
                        "map",
                        "update",
                        "pinned",
                        f"/sys/fs/bpf/{map_name}",
                        "key",
                        key,
                        "value",
                        value,
                        "any",
                    ],
                    raise_on_error=True,
                )
            except RuntimeError as exc:
                raise RuntimeError(
                    f"BPF map update failed for {map_name}[{key}]: {exc}"
                ) from exc

    def open_ring_buffer(self):
        """Return an iterator over resource guard events."""
        return iter(())
