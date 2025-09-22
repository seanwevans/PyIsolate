import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from pyisolate import policy


def test_policy_import_and_fs(tmp_path):
    p = (
        policy.Policy()
        .allow_import("math")
        .allow_import("pathlib")
        .allow_fs(str(tmp_path))
    )
    f = tmp_path / "data.txt"
    f.write_text("ok")

    sb = iso.spawn("pifs", policy=p)
    try:
        sb.exec("import math; post(math.sqrt(16))")
        assert sb.recv(timeout=1) == 4.0

        sb.exec(f"import pathlib; post(pathlib.Path({str(f)!r}).read_text())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec("import random")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)

        sb.exec("import pathlib; post(pathlib.Path('/etc/hosts').read_text())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_fs_sibling_not_allowed(tmp_path):
    allowed_dir = tmp_path / "foo"
    allowed_dir.mkdir()
    (allowed_dir / "data.txt").write_text("ok")

    sibling_dir = tmp_path / "foobar"
    sibling_dir.mkdir()
    bad_file = sibling_dir / "data.txt"
    bad_file.write_text("nope")

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-sibling", policy=p)
    try:
        sb.exec(f"post(open({str((allowed_dir / 'data.txt').resolve())!r}).read())")
        assert sb.recv(timeout=1) == "ok"

        sb.exec(f"post(open({str(bad_file.resolve())!r}).read())")
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()


def test_fs_allows_creating_new_files(tmp_path):
    allowed_dir = tmp_path / "allowed"
    allowed_dir.mkdir()
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()

    allowed_target = allowed_dir / "new.txt"
    blocked_target = blocked_dir / "blocked.txt"

    p = policy.Policy().allow_fs(str(allowed_dir))
    sb = iso.spawn("pifs-create", policy=p)
    try:
        sb.exec(
            (
                f"path = {str(allowed_target)!r}\n"
                "with open(path, 'w') as fh:\n"
                "    fh.write('hello world')\n"
                "with open(path) as fh:\n"
                "    post(fh.read())\n"
            )
        )
        assert sb.recv(timeout=1) == "hello world"

        sb.exec(
            (
                f"path = {str(blocked_target)!r}\n"
                "with open(path, 'w') as fh:\n"
                "    fh.write('nope')\n"
            )
        )
        with pytest.raises(iso.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.close()

    assert allowed_target.read_text() == "hello world"
    assert not blocked_target.exists()
