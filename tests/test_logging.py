import logging

from pyisolate.logging import setup_structured_logging


def test_setup_structured_logging():
    root = logging.getLogger()
    # Remove any existing handlers to ensure basicConfig configures one
    for h in list(root.handlers):
        root.removeHandler(h)
    setup_structured_logging()
    assert root.level == logging.INFO
    assert root.handlers
