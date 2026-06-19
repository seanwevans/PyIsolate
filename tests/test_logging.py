import json
import logging

from pyisolate.logging import JSONFormatter, setup_structured_logging


def test_structured_log_output_is_valid_json():
    record = logging.LogRecord(
        name='comp"x',
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='he said "hi"\nsecond line \\ backslash',
        args=(),
        exc_info=None,
    )
    line = JSONFormatter().format(record)
    parsed = json.loads(line)  # must not raise on quotes/newlines/backslashes
    assert parsed["message"] == 'he said "hi"\nsecond line \\ backslash'
    assert parsed["component"] == 'comp"x'
    assert parsed["level"] == "INFO"


def test_setup_structured_logging():
    root = logging.getLogger()
    # Remove any existing handlers to ensure basicConfig configures one
    for h in list(root.handlers):
        root.removeHandler(h)
    setup_structured_logging()
    assert root.level == logging.INFO
    assert root.handlers
