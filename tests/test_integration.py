import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def test_echo_example(capsys):
    runpy.run_path(str(ROOT / "examples" / "echo.py"), run_name="__main__")
    out = capsys.readouterr().out
    assert "Hello from sandbox" in out
