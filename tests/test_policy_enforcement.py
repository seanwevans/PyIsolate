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
