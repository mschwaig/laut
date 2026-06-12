import json
from concurrent.futures import ThreadPoolExecutor
from typing import Callable
from functools import wraps

# `json` is already in scope from the NixOS test driver's preamble.

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
# the outputs locally. Read the output paths off the LOCAL drv file
# (never asking the cache for drv files) and copy only the outputs from
# the cache — those carry Nix's narinfo signatures the substituter
# verifies on its own. CA verification operates purely on signed claims
# and needs no content.
if addressing == "ia":
    # The verifier walks every udrv in the drv tree (not just the root), and
    # build_ia_substitution invokes the closure walker on each udrv's outputs.
    # That means we need every non-FOD output's runtime closure locally, not
    # just the root's. Pull the recursive drv show, harvest every output path
    # whose drv has populated paths (i.e. IA outputs — FOD outputs we resolve
    # by declared hash and don't need locally), and `nix copy` them. Runtime
    # closure follows transitively per copied path.
    drv_json = json.loads(
        verifier.succeed(f"nix derivation show --recursive {drv_path}")
    )
    out_paths = []
    for entry in drv_json.values():
        for out in entry["outputs"].values():
            path = out.get("path")
            if path is None:
                continue
            # Skip FOD outputs (anything with a declared hash). The verifier's
            # IA pipeline resolves FODs via their declared path/hash without
            # calling the closure walker, so we don't need them locally — and
            # the post-build cache doesn't carry them anyway.
            if out.get("hash") is not None or out.get("hashAlgo") is not None:
                continue
            out_paths.append(path)
    verifier.succeed(
        "nix copy --no-check-sigs --from \"{}\" {}".format(
            cacheStoreUrl, " ".join(out_paths)
        )
    )

verify_cmd = f"laut verify --cache \"{cacheStoreUrl}\" --trusted-key {builderA_pub} --trusted-key {builderB_pub} {drv_path}"
output = verifier.succeed(verify_cmd)
print(f"laut verify output:\n{output}")

# verifier.fail("nix path-info cowsayPackage")
# verifier.succeed(f"nix store info --store '{cacheStoreUrl}' >&2")
# verifier.succeed(f"nix copy --no-check-sigs --from '{cacheStoreUrl}' cowsayPackage")
# verifier.succeed("nix path-info cowsayPackage")
