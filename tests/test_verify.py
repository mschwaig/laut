import json
from pathlib import Path
from typing import Optional
from unittest.mock import Mock
from laut.verification.verification import build_unresolved_tree, verify_tree
from laut.nix import commands

from laut.cli import read_public_key

import pytest

ca_data_file = Path(__file__).parent / "data" / "drv_lookup" / "hello-ca-recursive-unresolved.drv"

signature_folder = Path(__file__).parent.parent / "tests" / "data" / "traces" / "signatures"

if not (signature_folder.exists() and signature_folder.is_dir()):
    ValueError("Signature folder does not exist!")

@pytest.fixture
def mock_derivation_lookup(monkeypatch):
    """
    Fixture that mocks get_derivation to return appropriate data from hello-ca-recursive-unresolved.drv
    based on the requested derivation path.
    """
    def _get_derivation_mock(drv_path, recursive):
        # Load the entire recursive derivation data
        with open(ca_data_file) as f:
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
    """Fixture that mocks fetch_resolved_trace_signatures to return signature data from test files."""
    def _fetch_signatures_mock(_cache_url, input_hash: str) -> Optional[str]:
        signature_file = signature_folder / input_hash
        try:
            with open(signature_file) as f:
                signature_data = f.read()
                
                return signature_data
        except FileNotFoundError as e:
            print(f"Signature not found: {e}")
            return None

    mock = Mock(side_effect=_fetch_signatures_mock)
    monkeypatch.setattr("laut.verification.fetch_signatures.fetch_resolved_trace_signature_from_s3_bucket", mock)
    monkeypatch.setattr('laut.config.config.cache_urls', [ "mock_url" ])

    return mock

@pytest.fixture
def mock_config_debug(monkeypatch):
    trusted_keys = [ read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public")) ]
    monkeypatch.setattr('laut.config.config.debug', True)
    monkeypatch.setattr('laut.config.config.preimage_index', Path(__file__).parent.parent / "tests" / "data" / "traces" / "lookup_by_name" / "builderA_bcda8d54470fea3b.json")
    monkeypatch.setattr('laut.config.config.trusted_keys', trusted_keys)

def test_verify_ca_drv_small(mock_derivation_lookup, mock_config_debug, mock_signature_fetch):
    with open(ca_data_file) as f:
        hello_recursive = json.load(f)

    trust_model = read_public_key(str(Path(__file__).parent.parent / "testkeys" / "builderA_key.public"))
    #drv = build_unresolved_tree("/nix/store/ppliqnlksscm1hy0s9qpghbdxw3r3c2w-bootstrap-stage0-binutils-wrapper-.drv", hello_recursive)

    # there are multiple things that are called -bootstrap-stage1-stdenv-linux.drv
    # I assume this is because two different 'versions' of a bunch of derivations are used
    # as part of the bootstrap
    drv = build_unresolved_tree("/nix/store/p3y81mafk8jbj6r71xba1hailj5z0k09-bootstrap-stage1-stdenv-linux.drv", hello_recursive)

    list = verify_tree(drv)

    assert len(list) == 1
    resolved_derivaiton = list[0]
    assert resolved_derivaiton.input_hash == "JYBmi8474Lbjr5PgVGchx7hnGSGOmkqNLJAXKw9Pca4"

def test_verify_ca_drv_large(mock_derivation_lookup, mock_signature_fetch, mock_config_debug):
    with open(ca_data_file) as f:
        hello_recursive = json.load(f)
    # TODO: pass this in via mock

    drv = build_unresolved_tree("/nix/store/db2kl68nls8svahiyac77bdxdabzar71-hello-2.12.1.drv", hello_recursive)

    list = verify_tree(drv)

    assert len(list) == 1
    resolved_derivaiton = list[0]
    assert resolved_derivaiton.input_hash == "qAL8DbnetBrnMinLRt7mR4EusJo_w64fOUxo-pFT0ik"
