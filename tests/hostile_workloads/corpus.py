"""Executable hostile snippets that should be boring to PyIsolate.

Each workload is intentionally small and deterministic: the goal is not to
weaponize the test process, but to keep a regression corpus of behaviors that
real attackers routinely try against language-level sandboxes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class HostileWorkload:
    """A single hostile guest program and the sandbox outcome it must trigger."""

    name: str
    category: str
    source: str
    expected_exception: str = "PolicyError"
    allowed_imports: tuple[str, ...] | None = None
    spawn_kwargs: dict[str, Any] = field(default_factory=dict)
    policy: str | None = None


HOSTILE_WORKLOADS: tuple[HostileWorkload, ...] = (
    HostileWorkload(
        name="object_graph_import_escape",
        category="escape_attempt",
        source=(
            "# Reconnaissance through object.__subclasses__ must not become an import escape.\n"
            "classes = (1).__class__.__mro__[1].__subclasses__()\n"
            "__import__('os')\n"
            "post(len(classes))\n"
        ),
        allowed_imports=(),
    ),
    HostileWorkload(
        name="dunder_import_abuse",
        category="import_abuse",
        source="__import__('os').system('echo escaped')",
        allowed_imports=("math",),
    ),
    HostileWorkload(
        name="fork_bomb_primitive",
        category="fork_bomb",
        source="import os\nfor _ in range(3):\n    os.fork()\npost('forked')",
        allowed_imports=("os",),
    ),
    HostileWorkload(
        name="thread_bomb_quota",
        category="fork_bomb",
        source=(
            "import threading\n"
            "for _ in range(3):\n"
            "    threading.Thread(target=lambda: None).start()\n"
            "post('threaded')\n"
        ),
        expected_exception="ChildWorkExceeded",
        allowed_imports=("threading",),
        spawn_kwargs={"child_work_max": 0},
    ),
    HostileWorkload(
        name="anonymous_mmap_allocation",
        category="mmap_trick",
        source="import mmap\npost(mmap.mmap(-1, 1 << 30))",
        allowed_imports=("mmap",),
    ),
    HostileWorkload(
        name="raw_socket_connect",
        category="socket_attempt",
        source="import socket\ns = socket.socket()\ns.connect(('203.0.113.10', 443))",
        allowed_imports=("socket",),
    ),
    HostileWorkload(
        name="socket_create_connection_helper",
        category="socket_attempt",
        source="import socket\nsocket.create_connection(('203.0.113.10', 443), timeout=0.01)",
        allowed_imports=("socket",),
    ),
    HostileWorkload(
        name="symlink_escape_to_host_file",
        category="symlink_race",
        source="post(open({blocked_symlink!r}).read())",
        policy="tmp_allowed_dir",
    ),
    HostileWorkload(
        name="pickle_gadget_loader",
        category="pickle_ctypes_cffi_dlopen",
        source=(
            "import pickle\n"
            "payload = b'cos\\nsystem\\n(S\\'echo pickle_escape\\'\\ntR.'\n"
            "pickle.loads(payload)\n"
        ),
        allowed_imports=("pickle",),
    ),
    HostileWorkload(
        name="ctypes_dlopen",
        category="pickle_ctypes_cffi_dlopen",
        source="import ctypes\nctypes.CDLL('libc.so.6').system(b'echo ctypes_escape')",
        allowed_imports=("ctypes",),
    ),
    HostileWorkload(
        name="cffi_dlopen",
        category="pickle_ctypes_cffi_dlopen",
        source="import cffi\nffi = cffi.FFI()\nffi.dlopen('libc.so.6')",
        allowed_imports=("cffi",),
    ),
    HostileWorkload(
        name="native_extension_crash_probe",
        category="native_extension_crash",
        source="import _testcapi\n_testcapi.crash_no_current_thread()",
        allowed_imports=("_testcapi",),
    ),
    HostileWorkload(
        name="os_open_bypasses_builtin_open",
        category="escape_attempt",
        source="import os\nfd = os.open('/etc/hosts', os.O_RDONLY)\npost(os.read(fd, 32))",
        allowed_imports=("os",),
    ),
    HostileWorkload(
        name="subprocess_without_capability",
        category="escape_attempt",
        source="import subprocess\nsubprocess.run(['sh', '-c', 'echo subprocess_escape'])",
        allowed_imports=("subprocess",),
    ),
)
