import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from helper_module import add as plain_add
from helper_module import slow_identity, stage_one, stage_two

import pyisolate as iso

add = iso.sandbox(timeout=0.1)(plain_add)


def test_sandbox_decorator():
    assert add(2, 3) == 5


def test_pipeline_run():
    pipe = iso.Pipeline()
    pipe.add_stage(stage_one)
    pipe.add_stage(stage_two)
    result = pipe.run(3)
    assert result == 8


def test_sandbox_decorator_concurrent_calls_use_unique_names():
    slow = iso.sandbox(timeout=1)(slow_identity)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(slow, range(8)))

    assert results == list(range(8))


def test_pipeline_run_concurrent_calls_use_unique_stage_names():
    pipe = iso.Pipeline()
    pipe.add_stage(slow_identity)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(pipe.run, range(8)))

    assert results == list(range(8))
