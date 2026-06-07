"""Dedicated VM test for `laut verify --debug-preimage-corpus`.

Tampers one trace's signed-preimage so the verifier's expected hash no longer
has a valid signature, then runs verify with --debug-preimage-corpus pointed
at the same on-disk cache. The probe should fire and difft should surface
the tamper marker we injected.
"""

# Verifier only — no HTTP cache. We use file:// throughout.
verifier.start()
verifier.wait_for_unit("default.target")

# Copy the on-disk cache produced by the sign-test onto the verifier.
verifier.copy_from_host(binaryCacheData, "/var/lib")
verifier.succeed("chmod -R 755 /var/lib/cache")
verifier.succeed("test -d /var/lib/cache/traces")

# Run the writePython3Bin-wrapped tamper helper (`tamper-preimage` is on PATH
# because of the test's verifierExtraConfig). It appends a unique marker to
# the first trace's signed `rdrv_aterm_ca_preimage`, so the corpus has a
# divergent preimage but the signature for that hash no longer verifies.
TAMPER_MARKER = "LAUT_DEBUG_TAMPER_MARKER_98c4e3"
tamper_output = verifier.succeed(
    f"tamper-preimage /var/lib/cache/traces {TAMPER_MARKER}"
)
print(f"tamper output:\n{tamper_output}")

# Run verify pointing at the on-disk cache. We expect failure (the tampered
# signature is invalid for the hash it lives under) and probe activation.
debug_cmd = (
    f"laut verify "
    f"--cache 'file:///var/lib/cache' "
    f"--trusted-key {builderA_pub} --trusted-key {builderB_pub} "
    f"--debug-preimage-corpus 'file:///var/lib/cache' "
    f"--debug-out-dir /tmp/laut-debug "
    f"$(nix-instantiate '<nixpkgs-ca>' -A {packageToBuild}) 2>&1"
)
debug_output = verifier.fail(debug_cmd)
print(f"laut verify --debug-preimage-corpus output:\n{debug_output}")

assert "[laut debug]" in debug_output, (
    "expected debug probe to fire on signature miss; stderr did not "
    "contain '[laut debug]'"
)
assert TAMPER_MARKER in debug_output, (
    f"expected difft output to surface the tamper marker {TAMPER_MARKER!r} "
    "but it was absent from stderr — corpus building or difft invocation "
    "must have failed"
)

# Verify the on-disk artifact dir was populated.
verifier.succeed("test -d /tmp/laut-debug")
verifier.succeed("test -n \"$(find /tmp/laut-debug -mindepth 2 -type f)\"")
