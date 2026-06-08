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
verify_cmd = f"laut verify --cache \"{cacheStoreUrl}\" --trusted-key {builderA_pub} --trusted-key {builderB_pub} $(nix-instantiate '{nixpkgs_attr}' -A {packageToBuild})"
output = verifier.succeed(verify_cmd)
print(f"laut verify output:\n{output}")

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
