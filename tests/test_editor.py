import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyisolate.editor import check_fs, check_tcp, parse_policy


def test_fs_allow_rule():
    p = parse_policy("fs:\n  - allow: '/tmp/*.txt'")
    assert check_fs(p, "/tmp/test.txt")
    assert not check_fs(p, "/tmp/x.bin")


def test_net_connect_rule():
    p = parse_policy("net:\n  - connect: '127.0.0.1:80'")
    assert check_tcp(p, "127.0.0.1:80")
    assert not check_tcp(p, "10.0.0.1:80")
