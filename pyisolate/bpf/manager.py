"""eBPF loader and hot‑reloader.

This module compiles a very small eBPF program and attempts to attach it via
``bpftool``.  The build is intentionally simple and serves purely as a proof of
concept used by the tests.  ``bpftool`` and ``llvm-objdump`` may not be
available on the test system; any missing executables are therefore ignored.
"""

import json
import subprocess
from pathlib import Path


class BPFManager:
    """Compile and manage a minimal eBPF program.

    Compilation and skeleton generation are cached so that subsequent
    instances can reuse the pre-built object.
    """

    _SKEL_CACHE: dict[Path, str] = {}

    def __init__(self):
        self.loaded = False
        self.policy_maps: dict[str, str] = {}
        self._src = Path(__file__).with_name("dummy.bpf.c")
        self._obj = Path(__file__).with_name("dummy.bpf.o")
        self._skel = Path(__file__).with_name("dummy.skel.h")
        self.skeleton = ""
        self._filter_src = Path(__file__).with_name("syscall_filter.bpf.c")
        self._filter_obj = Path(__file__).with_name("syscall_filter.bpf.o")
        self._guard_src = Path(__file__).with_name("resource_guard.bpf.c")
        self._guard_obj = Path(__file__).with_name("resource_guard.bpf.o")

    # internal helper
    def _run(self, cmd: list[str]) -> bool:
        """Run a subprocess command and report success."""
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Missing tools or kernel permissions are ignored in the stub
            return False

    def load(self) -> None:
        """Compile and attempt to attach the eBPF programs."""
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
        if self._src not in self._SKEL_CACHE:
            ok &= self._run(compile_cmd)
            skel_cmd = [
                "sh",
                "-c",
                f"bpftool gen skeleton {self._obj} > {self._skel}",
            ]
            ok &= self._run(skel_cmd)
            if ok and self._skel.exists():
                try:
                    self._SKEL_CACHE[self._src] = self._skel.read_text()
                except OSError:
                    self._SKEL_CACHE[self._src] = ""
            self.skeleton = self._SKEL_CACHE.get(self._src, "")
        else:
            self.skeleton = self._SKEL_CACHE[self._src]

        ok &= self._run(filter_compile)
        ok &= self._run(guard_compile)
        ok &= self._run(["llvm-objdump", "-d", str(self._obj)])
        ok &= self._run(["llvm-objdump", "-d", str(self._filter_obj)])
        ok &= self._run(["llvm-objdump", "-d", str(self._guard_obj)])
        ok &= self._run(
            ["bpftool", "prog", "load", str(self._obj), "/sys/fs/bpf/dummy"]
        )
        ok &= self._run(
            [
                "bpftool",
                "prog",
                "load",
                str(self._filter_obj),
                "/sys/fs/bpf/syscall_filter",
            ]
        )
        ok &= self._run(
            ["bpftool", "prog", "load", str(self._guard_obj), "/sys/fs/bpf/resource_guard"]
        )
        self.loaded = ok

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
        # Replace the active policy entirely to drop removed entries
        self.policy_maps = data
        for key, val in data.items():
            self._run(
                [
                    "bpftool",
                    "map",
                    "update",
                    "pinned",
                    f"/sys/fs/bpf/{key}",
                    "key",
                    "0",
                    "value",
                    str(val),
                    "any",
                ]
            )

    def open_ring_buffer(self):
        """Return an iterator over resource guard events."""
        return iter(())
