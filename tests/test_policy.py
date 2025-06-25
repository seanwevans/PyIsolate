import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

import pyisolate.policy as policy


def test_policy_methods_chain():
    p = policy.Policy()
    assert p.allow_fs('/tmp') is p
    assert p.allow_tcp('127.0.0.1') is p


def test_policy_refresh_invalid(tmp_path):
    bad = tmp_path / 'bad.yml'
    bad.write_text('invalid')
    with pytest.raises(ValueError):
        policy.refresh(str(bad))
