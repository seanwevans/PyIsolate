import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pyisolate as iso
from helper_module import add as plain_add, stage_one, stage_two

add = iso.sandbox()(plain_add)


def test_sandbox_decorator():
    assert add(2, 3) == 5


def test_pipeline_run():
    pipe = iso.Pipeline()
    pipe.add_stage(stage_one)
    pipe.add_stage(stage_two)
    result = pipe.run(3)
    assert result == 8
