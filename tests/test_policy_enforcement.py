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
