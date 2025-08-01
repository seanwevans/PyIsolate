import pytest

from pyisolate import errors
from pyisolate.runtime.thread import _sigxcpu_handler


def test_sigxcpu_handler_raises():
    with pytest.raises(errors.CPUExceeded):
        _sigxcpu_handler(None, None)
