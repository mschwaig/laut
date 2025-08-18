#!/usr/bin/env python3
"""
Generate test data with both JSON and ATerm representations.

This script reads the output of `nix derivation show --recursive` from stdin,
and generates two files:
1. The original JSON data (pass-through)
2. A JSON file mapping derivation paths to their ATerm representations
"""

import json
import subprocess
import sys
from pathlib import Path


def get_derivation_aterm(drv_path):
    """Get the ATerm representation of a derivation using nix store cat."""
    result = subprocess.run(
        ['nix', '--extra-experimental-features', 'nix-command', 'store', 'cat', drv_path],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output-json-file> <output-aterm-json-file>", file=sys.stderr)
        print("Reads nix derivation show JSON from stdin", file=sys.stderr)
        sys.exit(1)
    
    output_json_file = sys.argv[1]
    output_aterm_file = sys.argv[2]
    
    # Read JSON from stdin
    print("Reading derivation data from stdin...", file=sys.stderr)
    derivations = json.load(sys.stdin)
    
    print(f"Found {len(derivations)} derivations", file=sys.stderr)
    
    # Save the original JSON data
    with open(output_json_file, 'w') as f:
        json.dump(derivations, f, indent=2)
    print(f"Saved JSON data to {output_json_file}", file=sys.stderr)
    
    # Create a mapping of derivation paths to their ATerm representations
    aterm_data = {}
    
    for i, drv_path in enumerate(derivations.keys(), 1):
        print(f"Processing {i}/{len(derivations)}: {drv_path}", file=sys.stderr)
        try:
            aterm = get_derivation_aterm(drv_path)
            aterm_data[drv_path] = aterm
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to get ATerm for {drv_path}: {e}", file=sys.stderr)
            # Continue processing other derivations
    
    # Save ATerm data to JSON file
    with open(output_aterm_file, 'w') as f:
        json.dump(aterm_data, f, indent=2)
    
    print(f"Saved ATerm data for {len(aterm_data)} derivations to {output_aterm_file}", file=sys.stderr)


if __name__ == "__main__":
    main()