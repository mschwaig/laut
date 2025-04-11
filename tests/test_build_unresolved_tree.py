import json
from pathlib import Path
from laut.verification.verification import build_unresolved_tree
from laut.cli import read_public_key

import linecache
import os
import tracemalloc

from laut.config import config
import pytest

ia_data_file = Path(__file__).parent / "data" / "drv_lookup" / "hello-ia-recursive-unresolved.drv"
ca_data_file = Path(__file__).parent / "data" /"drv_lookup" /  "hello-ca-recursive-unresolved.drv"

@pytest.fixture
def mock_config_allow_ia(monkeypatch):
    monkeypatch.setattr('laut.config.config.allow_ia', True)

def test_ia_drv_tree_small_ia_raises_exception():
    with open(ia_data_file) as f:
        hello_recursive = json.load(f)

    with pytest.raises(ValueError, match="cannot handle IA derivations yet"):
        build_unresolved_tree("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv", hello_recursive)

def test_ia_drv_tree_small_ia_allowed(mock_config_allow_ia):
    with open(ia_data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv", hello_recursive)

def test_ca_drv_tree_small():
    with open(ca_data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/ppliqnlksscm1hy0s9qpghbdxw3r3c2w-bootstrap-stage0-binutils-wrapper-.drv", hello_recursive)

def test_ca_large():
    with open(ca_data_file) as f:
        hello_recursive = json.load(f)

    drv = build_unresolved_tree("/nix/store/db2kl68nls8svahiyac77bdxdabzar71-hello-2.12.1.drv", hello_recursive)

def test_loadKey():
    key = read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"))
    print(key)
