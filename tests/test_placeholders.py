from laut.nix.deep_constructive_trace import get_DCT_input_hash
from laut.nix.placeholder import (
    from_drv_path_and_output,
    encode_to_string
)

def test_downstream_placeholder_generation():
    placeholder = from_drv_path_and_output("/nix/store/g1w7hy3qg1w7hy3qg1w7hy3qg1w7hy3q-foo.drv", "out")
    assert placeholder == "/0c6rn30q4frawknapgwq386zq358m8r6msvywcvc89n6m5p2dgbz"

def test_nix32():
    nix32_repr = encode_to_string(bytes.fromhex("d86b3392c1202e8ff5a423b302e6284db7f8f435ea9f39b5b1b20fd3ac36dfcb"))
    assert nix32_repr == "1jyz6snd63xjn6skk7za6psgidsd53k05cr3lksqybi0q6936syq"