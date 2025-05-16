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

@run_in_background
def boot_and_configure(builder):
  builder.start()
  builder.wait_for_unit("network.target")

  builder.succeed(f"curl -fv http://cache:{cachePort}/minio/health/ready")

  builder.wait_for_unit("default.target")

@run_in_background
def build_and_upload(builder):
  # builder.succeed("nix build --expr 'derivation { name = \"test\"; builder = \"/bin/sh\"; args = [ \"-c\" \"echo $RANDOM > $out\" ]; system = \"x86_64-linux\"; __contentAddressed = true; }' --secret-key-files \"/etc/nix/private-key\" --no-link --print-out-paths")
  builder.succeed(f"nix build -f '<nixpkgs-ca>' {packageToBuild} --secret-key-files \"/etc/nix/private-key\" -L")

if isMemoryConstrained:
  future = boot_and_configure(builderA)
  future.result()
  future = build_and_upload(builderA)
  future.result()
  builderA.shutdown()
  future = boot_and_configure(builderB)
  future.result()
  future = build_and_upload(builderB)
  future.result()
  builderB.shutdown()
else:
  future1, future2 = boot_and_configure(builderA), boot_and_configure(builderB)
  future1.result()
  future2.result()
  future1, future2 = build_and_upload(builderA), build_and_upload(builderB)
  future1.result()
  future2.result()
  builderA.shutdown()
  builderB.shutdown()

# for now we only care about extracting the cache outputs from this test
# and using them as input for the unit and integration tests in python
verifier.start()
verifier.wait_for_unit("default.target")

verify_cmd = f"laut verify --cache \"{cacheStoreUrl}\" --trusted-key {builderA_pub} $(nix-instantiate '<nixpkgs-ca>' -A {packageToBuild})"
output = verifier.succeed(verify_cmd)
print(f"laut verify output:\n{output}")

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
