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
    """Compile and manage a minimal eBPF program."""

    def __init__(self):
        self.loaded = False
        self.policy_maps: dict[str, str] = {}
        self._src = Path(__file__).with_name("dummy.bpf.c")
        self._obj = Path(__file__).with_name("dummy.bpf.o")

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
        """Compile and attempt to attach the eBPF program."""
        compile_cmd = [
            "clang",
            "-target",
            "bpf",
            "-O2",
            "-c",
            str(self._src),
            "-o",
            str(self._obj),
        ]
        ok = True
        ok &= self._run(compile_cmd)
        ok &= self._run(["llvm-objdump", "-d", str(self._obj)])
        ok &= self._run(["bpftool", "prog", "load", str(self._obj), "/sys/fs/bpf/dummy"])
        self.loaded = ok

    def hot_reload(self, policy_path: str) -> None:
        """Refresh maps based on a policy JSON file."""
        if not self.loaded:
            raise RuntimeError("BPF not loaded")
        with open(policy_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
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
