from laut.nix.deep_constructive_trace import get_nix_path_input_hash
from lautr import (
    hash_upstream_placeholder
)

def test_downstream_placeholder_generation():
    placeholder = hash_upstream_placeholder("/nix/store/g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo.drv", "out")
    assert placeholder == "/0c6rn30q4frawknapgwq386zq358m8r6msvywcvc89n6m5p2dgbz"
