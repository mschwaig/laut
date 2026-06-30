#!/usr/bin/env bash
# Collect diagnostics from a failed VM test run.
#
# Usage:
#   ./collect-vm-test-logs.sh <test-name> [output-zip]
#
# Examples:
#   ./collect-vm-test-logs.sh medium-ia-verify
#   ./collect-vm-test-logs.sh large-ia-verify /tmp/my-diagnostics.zip
#
# Collects:
#   - The sign test's cache output (store paths + traces + narinfo)
#   - The sign test log (from nix log)
#   - The verify test log (from nix log)
#
# The sign test name is derived from the verify test name by replacing
# "-verify" with "-sign".

set -euo pipefail

VERIFY_TEST="${1:?Usage: $0 <test-name> [output-zip]}"
# Strip optional "laut-" prefix and any checks.x86_64-linux. prefix
VERIFY_TEST="${VERIFY_TEST#laut-}"
VERIFY_TEST="${VERIFY_TEST#checks.x86_64-linux.}"

OUTPUT="${2:-$(pwd)/${VERIFY_TEST}-diagnostics.zip}"

# Derive sign test name: "medium-ia-verify" -> "medium-ia-sign"
SIGN_TEST="${VERIFY_TEST/-verify/-sign}"

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Collecting diagnostics for: $VERIFY_TEST"
echo "Sign test: $SIGN_TEST"
echo "Output: $OUTPUT"
echo ""

# 1. Sign test log
echo "Fetching sign test log..."
nix log ".#checks.x86_64-linux.${SIGN_TEST}" > "$TMPDIR/sign-log.txt" 2>&1 || \
  echo "  (failed to fetch sign log)"

# 2. Verify test log
echo "Fetching verify test log..."
nix log ".#checks.x86_64-linux.${VERIFY_TEST}" > "$TMPDIR/verify-log.txt" 2>&1 || \
  echo "  (failed to fetch verify log)"

# 3. Sign test cache contents
echo "Fetching sign test cache output..."
SIGN_CACHE_DRV=$(nix derivation show ".#checks.x86_64-linux.${SIGN_TEST}" --json 2>/dev/null \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(list(d.values())[0]['outputs']['cache']['path'])" 2>/dev/null) || true

if [ -n "${SIGN_CACHE_DRV:-}" ]; then
  echo "  Cache path: $SIGN_CACHE_DRV"
  # Copy the cache output to a local directory (realises it if needed)
  nix copy --to "file://$TMPDIR/cache" "$SIGN_CACHE_DRV" 2>/dev/null || \
    nix-store --realise "$SIGN_CACHE_DRV" --add-root "$TMPDIR/cache-root" 2>/dev/null || \
    echo "  (failed to realise cache output, trying nix build)"

  if [ ! -d "$TMPDIR/cache" ]; then
    # Fallback: just realise the store path and list its contents
    nix build ".#checks.x86_64-linux.${SIGN_TEST}" --no-link 2>/dev/null || true
    SIGN_CACHE_PATH=$(nix path-info ".#checks.x86_64-linux.${SIGN_TEST}.cache" 2>/dev/null || true)
    if [ -n "${SIGN_CACHE_PATH:-}" ] && [ -d "$SIGN_CACHE_PATH" ]; then
      cp -r "$SIGN_CACHE_PATH" "$TMPDIR/cache" 2>/dev/null || \
        echo "  (failed to copy cache contents)"
    fi
  fi
else
  echo "  (could not determine cache path, trying nix build output)"
  nix build ".#checks.x86_64-linux.${SIGN_TEST}" --no-link 2>/dev/null || \
    echo "  (nix build failed)"
  # Try to find the cache output among the build outputs
  for p in $(nix path-info ".#checks.x86_64-linux.${SIGN_TEST}*" 2>/dev/null || true); do
    if [ -d "$p" ] && [ -d "$p/traces" -o -d "$p/nar" ]; then
      echo "  Found cache at: $p"
      cp -r "$p" "$TMPDIR/cache" 2>/dev/null || true
      break
    fi
  done
fi

# 4. Also capture the store paths of the sign test outputs for reference
echo "Capturing sign test derivation info..."
nix derivation show ".#checks.x86_64-linux.${SIGN_TEST}" > "$TMPDIR/sign-derivation.json" 2>&1 || true
nix derivation show ".#checks.x86_64-linux.${VERIFY_TEST}" > "$TMPDIR/verify-derivation.json" 2>&1 || true

# 5. Zip everything
echo ""
echo "Creating archive..."
cd "$TMPDIR"
zip -r "$OUTPUT" . -x "cache-root" 2>/dev/null || true

echo ""
echo "Done! Archive at: $OUTPUT"
echo "Contents:"
unzip -l "$OUTPUT" 2>/dev/null | head -30
