import json
from pathlib import Path
from unittest.mock import Mock
from laut.verification.verification import build_unresolved_tree, verify_tree
from laut.nix import commands

from laut.cli import read_public_key

import pytest

@pytest.fixture
def mock_derivation_lookup(monkeypatch):
    """
    Fixture that mocks get_derivation to return appropriate data from hello-ca-recursive.drv
    based on the requested derivation path.
    """
    def _get_derivation_mock(drv_path, recursive):
        # Load the entire recursive derivation data
        data_file = Path(__file__).parent / "data" / "hello-ca-recursive.drv"
        with open(data_file) as f:
            all_derivations = json.load(f)
        if recursive:
            return all_derivations
        else:
            return all_derivations[drv_path]

    mock = Mock(side_effect=_get_derivation_mock)
    monkeypatch.setattr(commands, "get_derivation", mock)
    return mock

@pytest.fixture
def mock_signature_fetch(monkeypatch):
    """Fixture that mocks fetch_ct_signatures to return signature data from test files."""
    def _fetch_signatures_mock(input_hash: str) -> list:
        # Path to the signature file
        signature_file = Path(__file__).parent.parent.parent / "tests" / "traces" / "out4" / "builderA.json"
        
        try:
            with open(signature_file) as f:
                signature_data = json.load(f)
                
            # Return the signatures for the requested input hash if they exist
            if input_hash in signature_data:
                return [signature_data[input_hash]]
            else:
                return []
        except Exception as e:
            print(f"Error loading signatures: {e}")
            return []
    
    mock = Mock(side_effect=_fetch_signatures_mock)
    monkeypatch.setattr("laut.verification.verification.fetch_ct_signatures", mock)
    return mock

def test_verify_ca_drv_small(mock_derivation_lookup, mock_signature_fetch):
    data_file = Path(__file__).parent / "data" / "hello-ca-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)

    trust_model = read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"))
    #drv = build_unresolved_tree("/nix/store/iqzp8nwk1g18yi58hvp3plc8y2z1lwjz-bootstrap-stage0-binutils-wrapper-.drv", hello_recursive)
    #drv = build_unresolved_tree("/nix/store/0m4y3j4pnivlhhpr5yqdvlly86p93fwc-busybox.drv", hello_recursive)
    drv = build_unresolved_tree("/nix/store/wnylsz1bmayj1xprnbj7mg6wn5scmr2v-bootstrap-stage1-stdenv-linux.drv", hello_recursive)
    list = verify_tree(drv, trust_model)
    #tracemalloc.start()
    #snapshot = tracemalloc.take_snapshot()
    #display_top(snapshot)

def test_verify_ca_drv_large(mock_derivation_lookup, mock_signature_fetch):
    data_file = Path(__file__).parent / "data" / "hello-ca-recursive.drv"
    with open(data_file) as f:
        hello_recursive = json.load(f)
    trust_model = read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"))
    drv = build_unresolved_tree("/nix/store/ini9yln97fpf7ccwdv8hqbj3crfqvrcm-hello-2.12.1.drv", hello_recursive)
    #tracemalloc.start()
    list = verify_tree(drv, trust_model)
    #snapshot = tracemalloc.take_snapshot()
    #display_top(snapshot)
