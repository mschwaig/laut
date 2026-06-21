from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from functools import wraps

executor = ThreadPoolExecutor(max_workers=5)

def run_in_background(func: Callable):
  @wraps(func)
  def wrapper(*args, **kwargs):
    return executor.submit(func, *args, **kwargs)

  return wrapper

cache.start()
cache.forward_port(9000, 9000)
cache.wait_for_unit("http-cache-server")
cache.wait_for_open_port(cachePort)

cache.wait_for_unit("default.target")
cache.succeed("mkdir -p /var/lib/cache/traces /var/lib/cache/nar")
cache.succeed("systemctl stop http-cache-server.service")
cache.copy_from_host(binaryCacheData, "/var/lib")
cache.succeed("chmod -R 755 /var/lib/cache")
cache.succeed("systemctl start http-cache-server.service")

# for now we only care about extracting the cache outputs from this test
# and using them as input for the unit and integration tests in python
verifier.start()
verifier.wait_for_unit("default.target")

nixpkgs_attr = "<nixpkgs-ca>" if addressing == "ca" else "<nixpkgs>"

# Instantiate locally — this writes the full drv graph (root + transitive
# input drvs) into the verifier's own store. Trust comes from our nix
# binary evaluating local nixpkgs source, not from a remote cache.
drv_path = verifier.succeed(f"nix-instantiate '{nixpkgs_attr}' -A {packageToBuild}").strip()

# IA verification recomputes synthetic CA paths from local output bytes
# (the closure walker scans content), so we need the runtime closure of
# the root output(s) locally. The walker recurses by following
# `nix-store -q --references`, naturally covering every non-FOD store
# path in the transitive runtime closure.
#
# Build from the same nixpkgs the signer uses (`-f '<nixpkgs>'`).  This
# gives Nix the same derivation tree so it can substitute root outputs
# from the cache.  Intermediate paths from the VM store image may exist
# on disk without being registered in the Nix DB — the walker's
# auto-registration path handles those on-demand via `nix copy`.
if addressing == "ia":
    verifier.succeed(f"nix build -f '{nixpkgs_attr}' {packageToBuild} --substitute --no-link")

verify_cmd = f"laut verify --cache \"{cacheStoreUrl}\" --trusted-key {builderA_pub} --trusted-key {builderB_pub} {drv_path}"
output = verifier.succeed(verify_cmd)
print(f"laut verify output:\n{output}")

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
