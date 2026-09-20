from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable
from functools import wraps
import shlex

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
  build_complete = False
  try:
    if experimentEnabled:
      builder.succeed(f"laut-seed-inputs --seed {shlex.quote(storePathSeed)}")
      root = builder.succeed(
        f"nix-instantiate '{nixpkgs_attr}' -A {packageToBuild}"
      ).strip()
      builder.succeed(f"laut-experiment begin {shlex.quote(root)}")
      builder.succeed(
        "cp /var/lib/laut-seeded-inputs.json /var/lib/laut-experiment/seeded-inputs.json"
      )
    builder.succeed(f"nix build -f '{nixpkgs_attr}' {packageToBuild} --no-substitute --secret-key-files \"/etc/nix/private-key\" -L")
    build_complete = True
  finally:
    if experimentEnabled:
      # Retain partial evidence on failure; collect's status is not a hash verdict.
      status, output = builder.execute("laut-experiment collect")
      print(output)
      builder.copy_from_vm("/var/lib/laut-experiment", f"experiment/{builder.name}")
      if build_complete:
        assert status == 0, f"{builder.name}: incomplete experiment artifacts"

try:
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
    wait([future1, future2])
    future1.result()
    future2.result()
    future1, future2 = build_and_upload(builderA), build_and_upload(builderB)
    # Both builders must finish exporting before a failure tears down the VMs.
    wait([future1, future2])
    future1.result()
    future2.result()
    builderA.shutdown()
    builderB.shutdown()

  assert cache.succeed("ls -A /var/lib/cache/traces").split() == ["aterm"]
  cache.succeed(
      "test -n \"$(find /var/lib/cache/traces/aterm "
      "-maxdepth 1 -type f)\""
  )
finally:
  cache.copy_from_vm("/var/lib/cache", "")
  cache.shutdown()
