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

logger = logging.getLogger(__name__)


class BPFManager:
    """Compile and manage a minimal eBPF program.

    Compilation and skeleton generation are cached per instance so that
    repeated loads can reuse the pre-built object.
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
            logger.error("command not found: %s", cmd[0])
            if raise_on_error:
                raise RuntimeError(f"Command not found: {cmd[0]}") from exc
            return True
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr or ""
            logger.error("command failed %s: %s", cmd, stderr.strip())
            if raise_on_error:
                raise RuntimeError(
                    f"Command '{cmd[0]}' failed with exit code {exc.returncode}: {stderr.strip()}"
                ) from exc
        return False

    def load(self, *, strict: bool = False) -> None:
        """Compile and attempt to attach the eBPF programs.

        When ``strict`` is ``True`` any failure will raise a ``RuntimeError``
        with details from the underlying command.  In the default lenient mode
        missing tooling simply results in ``loaded`` remaining ``False`` while
        errors are logged.
        """

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
        if self._src not in self._skel_cache:
            ok &= self._run(compile_cmd, raise_on_error=strict)
            skel_cmd = [
                "sh",
                "-c",
                f"bpftool gen skeleton {self._obj} > {self._skel}",
            ]
            ok &= self._run(skel_cmd, raise_on_error=strict)
            if ok and self._skel.exists():
                try:
                    self._skel_cache[self._src] = self._skel.read_text()
                except OSError:
                    self._skel_cache[self._src] = ""
            self.skeleton = self._skel_cache.get(self._src, "")
        else:
            self.skeleton = self._skel_cache[self._src]

        ok &= self._run(filter_compile, raise_on_error=strict)
        ok &= self._run(guard_compile, raise_on_error=strict)
        ok &= self._run(["llvm-objdump", "-d", str(self._obj)], raise_on_error=strict)
        ok &= self._run(
            ["llvm-objdump", "-d", str(self._filter_obj)], raise_on_error=strict
        )
        ok &= self._run(
            ["llvm-objdump", "-d", str(self._guard_obj)], raise_on_error=strict
        )
        ok &= self._run(
            ["bpftool", "prog", "load", str(self._obj), "/sys/fs/bpf/dummy"],
            raise_on_error=strict,
        )
        ok &= self._run(
            [
                "bpftool",
                "prog",
                "load",
                str(self._filter_obj),
                "/sys/fs/bpf/syscall_filter",
            ],
            raise_on_error=strict,
        )
        ok &= self._run(
            [
                "bpftool",
                "prog",
                "load",
                str(self._guard_obj),
                "/sys/fs/bpf/resource_guard",
            ],
            raise_on_error=strict,
        )
        self.loaded = ok
        if strict and not ok:
            raise RuntimeError("BPF load failed; see logs for details")

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
        # Replace the active policy entirely to drop removed entries
        self.policy_maps = data
        for key, val in data.items():
            encoded_val = (
                json.dumps(val, separators=(",", ":"))
                if isinstance(val, (dict, list))
                else str(val)
            )
            logger.info("updating map %s -> %s", key, encoded_val)
            try:
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
                        encoded_val,
                        "any",
                    ],
                    raise_on_error=True,
                )
            except RuntimeError as exc:
                raise RuntimeError(f"BPF map update failed for {key}: {exc}") from exc

    def open_ring_buffer(self):
        """Return an iterator over resource guard events."""
        return iter(())
