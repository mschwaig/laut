import json
from pathlib import Path
from laut.verification.verification import build_unresolved_tree
from laut.cli import read_public_key

import linecache
import os
import tracemalloc

from laut.config import config
import pytest

# memory usage tracing from https://stackoverflow.com/a/45679009
def display_top(snapshot, key_type='lineno', limit=10):
    snapshot = snapshot.filter_traces((
        tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
        tracemalloc.Filter(False, "<unknown>"),
    ))
    top_stats = snapshot.statistics(key_type)

    print("Top %s lines" % limit)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        # replace "/path/to/module/file.py" with "module/file.py"
        filename = os.sep.join(frame.filename.split(os.sep)[-2:])
        print("#%s: %s:%s: %.1f KiB"
              % (index, filename, frame.lineno, stat.size / 1024))
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print('    %s' % line)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print("%s other: %.1f KiB" % (len(other), size / 1024))
    total = sum(stat.size for stat in top_stats)
    print("Total allocated size: %.1f KiB" % (total / 1024))

@pytest.fixture
def mock_config_allow_ia(monkeypatch):
    monkeypatch.setattr('laut.config.config.allow_ia', True)

def test_ia_drv_tree_small_ia_raises_exception():
    data_file = Path(__file__).parent / "data" / "hello-ia-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)

    with pytest.raises(ValueError, match="cannot handle IA derivations yet"):
        build_unresolved_tree("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv", hello_recursive)

def test_ia_drv_tree_small_ia_allowed(mock_config_allow_ia):
    data_file = Path(__file__).parent / "data" / "hello-ia-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv", hello_recursive)

def test_ca_drv_tree_small():
    data_file = Path(__file__).parent / "data" / "hello-ca-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/ppliqnlksscm1hy0s9qpghbdxw3r3c2w-bootstrap-stage0-binutils-wrapper-.drv", hello_recursive)

def test_ca_large():
    data_file = Path(__file__).parent / "data" / "hello-ca-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/db2kl68nls8svahiyac77bdxdabzar71-hello-2.12.1.drv", hello_recursive)

def test_loadKey():
    key = read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"))
    print(key)
