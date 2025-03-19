import json
from pathlib import Path
from laut.nix.deep_constructive_trace import get_DCT_input_hash

import pytest
from loguru import logger
import _pytest.logging

def test_dct_input_hash():
    hash = get_DCT_input_hash("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv")
    assert hash == "fxz942i5pzia8cgha06swhq216l01p8d"
