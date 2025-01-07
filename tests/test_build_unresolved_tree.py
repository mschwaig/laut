import json
from pathlib import Path
from trace_signatures.verification import build_unresolved_tree

def test_simple():
   data_file = Path(__file__).parent / "data" / "hello-recursive.drv"
   with open(data_file) as f:
     hello_recursive = json.load(f)

   drv = build_unresolved_tree("/nix/store/fxz942i5pzia8cgha06swhq216l01p8d-bootstrap-stage1-stdenv-linux.drv", hello_recursive)
   #drv = build_unresolved_tree("/nix/store/lrrywp3k594k3295lh92lm7a387wk0j9-hello-2.12.1.drv", hello_recursive)