import pyisolate.operator as op


def test_operator_module():
    assert hasattr(op, "run_operator")
    assert callable(op.run_operator)
    assert hasattr(op, "scale_sandboxes")
