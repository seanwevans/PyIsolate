import pytest
from pyisolate.runtime.thread import _sigxcpu_handler
from pyisolate import errors


def test_sigxcpu_handler_raises():
    with pytest.raises(errors.CPUExceeded):
        _sigxcpu_handler(None, None)
