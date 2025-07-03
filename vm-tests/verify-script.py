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
cache.forward_port(9001, 9001)
cache.wait_for_unit("minio")
cache.wait_for_open_port(9002)
cache.wait_for_open_port(cachePort)

# configure cache
cache.succeed(f"mc config host add minio http://cache:{cachePort} {cacheAccessKey} {cacheSecretKey} --api s3v4")
cache.succeed("mc mb minio/binary-cache")
cache.succeed("mc anonymous set download minio/binary-cache") # allow public read

cache.wait_for_unit("default.target")
cache.succeed("systemctl stop minio.service")
#cache.succeed("mkdir -p /var/lib/minio/data/binary-cache/traces")
cache.copy_from_host(binaryCacheData, "/var/lib/minio")
cache.succeed("chown -R minio:minio /var/lib/minio/data")
cache.succeed("systemctl start minio.service")

# for now we only care about extracting the cache outputs from this test
# and using them as input for the unit and integration tests in python
verifier.start()
verifier.wait_for_unit("default.target")

verify_cmd = f"laut verify --cache \"{cacheStoreUrl}\" --trusted-key {builderA_pub} --trusted-key {builderB_pub} $(nix-instantiate '<nixpkgs-ca>' -A {packageToBuild})"
output = verifier.succeed(verify_cmd)
print(f"laut verify output:\n{output}")

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
