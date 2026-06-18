import py_compile
from pathlib import Path


def test_runtime_thread_module_compiles() -> None:
    path = Path(__file__).resolve().parents[1] / "pyisolate" / "runtime" / "thread.py"
    py_compile.compile(str(path), doraise=True)
