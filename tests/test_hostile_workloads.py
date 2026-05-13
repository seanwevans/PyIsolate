import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy
from tests.hostile_workloads import HOSTILE_WORKLOADS, HostileWorkload

_EXPECTED_EXCEPTIONS = {
    "ChildWorkExceeded": iso.ChildWorkExceeded,
    "PolicyError": iso.PolicyError,
}


def _spawn_for_case(case: HostileWorkload, tmp_path: Path):
    kwargs = dict(case.spawn_kwargs)
    source = case.source
    case_policy = None

    if case.policy == "tmp_allowed_dir":
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        blocked_symlink = allowed_dir / "hosts-link"
        blocked_symlink.symlink_to("/etc/hosts")
        source = source.format(blocked_symlink=str(blocked_symlink))
        case_policy = policy.Policy().allow_fs(str(allowed_dir))

    if case.allowed_imports is not None:
        kwargs["allowed_imports"] = list(case.allowed_imports)
    if case_policy is not None:
        kwargs["policy"] = case_policy

    sandbox = iso.spawn(f"hostile-{case.name[:40].replace('_', '-')}", **kwargs)
    return sandbox, source


@pytest.mark.adversarial
@pytest.mark.hostile
@pytest.mark.parametrize("case", HOSTILE_WORKLOADS, ids=lambda case: case.name)
def test_hostile_workload_corpus_is_rejected(case, tmp_path):
    expected = _EXPECTED_EXCEPTIONS[case.expected_exception]
    sandbox, source = _spawn_for_case(case, tmp_path)
    try:
        sandbox.exec(source)
        with pytest.raises(expected):
            sandbox.recv(timeout=1)
    finally:
        sandbox.close()


@pytest.mark.adversarial
@pytest.mark.hostile
def test_hostile_corpus_documents_required_categories():
    categories = {case.category for case in HOSTILE_WORKLOADS}
    assert {
        "escape_attempt",
        "import_abuse",
        "fork_bomb",
        "mmap_trick",
        "socket_attempt",
        "symlink_race",
        "pickle_ctypes_cffi_dlopen",
        "native_extension_crash",
    } <= categories
