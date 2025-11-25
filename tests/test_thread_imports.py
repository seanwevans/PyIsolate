import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

from pyisolate import errors
from pyisolate.policy import Policy
from pyisolate.runtime import thread


def test_policy_imports_applied_without_explicit_allowed_imports():
    policy = Policy(imports=["math"])
    sb = thread.SandboxThread("policy-imports", policy=policy)
    sb.start()
    try:
        sb.exec("import math; post(math.factorial(5))")
        assert sb.recv(timeout=1) == 120

        sb.exec("import os")
        with pytest.raises(errors.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.stop()


def test_reset_merges_policy_and_allowed_imports():
    sb = thread.SandboxThread("reset-imports", policy=Policy(imports=["math"]))
    sb.start()
    try:
        sb.exec("import math; post('ok')")
        assert sb.recv(timeout=1) == "ok"

        sb.reset(
            "reset-imports-2",
            policy=Policy(imports=["random"]),
            allowed_imports=["math"],
        )

        sb.exec("import random; post(random.choice([1, 2, 3]))")
        assert sb.recv(timeout=1) in {1, 2, 3}

        sb.exec("import math; post(math.isfinite(1.0))")
        assert sb.recv(timeout=1) is True

        sb.exec("import os")
        with pytest.raises(errors.PolicyError):
            sb.recv(timeout=1)
    finally:
        sb.stop()
