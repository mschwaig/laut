import json
from pathlib import Path
from laut.signing import extract_nix_version_from_NIX_CONFIG

import pytest
from loguru import logger
import _pytest.logging


def test_get_nix_version_from_NIX_CONFIG():
    path = Path(__file__).parent / "data" / "env_NIX_CONFIG.txt"
    NIX_CONFIG_env_var = path.read_text()
    result = extract_nix_version_from_NIX_CONFIG(NIX_CONFIG_env_var)
    assert result == ("lix", "2.91.1")
