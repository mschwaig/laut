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

cache.succeed("mkdir -p /var/lib/cache/traces /var/lib/cache/nar")
cache.succeed("echo 'StoreDir: /nix/store' > /var/lib/cache/nix-cache-info")
cache.succeed("echo 'WantMassQuery: 0' >> /var/lib/cache/nix-cache-info")
cache.succeed("echo 'Priority: 30' >> /var/lib/cache/nix-cache-info")

@run_in_background
def boot_and_configure(builder):
  builder.start()
  builder.wait_for_unit("network.target")

  builder.succeed(f"curl -fv http://cache:{cachePort}/nix-cache-info")

  builder.wait_for_unit("default.target")

nixpkgs_attr = "<nixpkgs-ca>" if addressing == "ca" else "<nixpkgs>"

@run_in_background
def build_and_upload(builder):
  # builder.succeed("nix build --expr 'derivation { name = \"test\"; builder = \"/bin/sh\"; args = [ \"-c\" \"echo $RANDOM > $out\" ]; system = \"x86_64-linux\"; __contentAddressed = true; }' --secret-key-files \"/etc/nix/private-key\" --no-link --print-out-paths")
  builder.succeed(f"nix build -f '{nixpkgs_attr}' {packageToBuild} --secret-key-files \"/etc/nix/private-key\" -L")

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

cache.copy_from_vm("/var/lib/cache", "")
cache.shutdown()

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
