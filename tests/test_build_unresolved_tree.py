import json
from pathlib import Path
from trace_signatures.verification import build_unresolved_tree

def test_simple():
   data_file = Path(__file__).parent / "data" / "hello-recursive.drv"
   with open(data_file) as f:
     hello_recursive = json.load(f)
   drv = build_unresolved_tree("/nix/store/4yvxza1jxha234jr2hhd3yi8mvil0zwc-hello-2.12.1.tar.gz.drv", hello_recursive)
   expected = 666
   result = 667
   assert result == expected