import pytest

from pyisolate import RestrictedExec, OwnershipError


def test_basic_arithmetic():
    r = RestrictedExec()
    r.exec("a = 1\nb = 2\nc = a + b")
    assert r.exec("c") == 3


def test_move_blocks_reuse():
    r = RestrictedExec()
    r.exec("x = 5\ny = move(x)")
    with pytest.raises(OwnershipError):
        r.exec("z = x")
