#!/usr/bin/env python3
import json
import os
import argparse
from collections import defaultdict
import base64

def process_json_files(input_dir, output_dir, key_field='drv_path', allow_duplicate_keys=False, debug=False):
    """
    Process JSON files and build consolidated objects by 'kid'.

    Args:
        input_dir: Directory containing the input JSON files
        output_dir: Directory to save the output JSON files
        key_field: Field to use as keys in the output JSON ('drv_path', 'in', or 'drv_name')
        allow_duplicate_keys: Allow duplicate keys in output by storing values in arrays
        debug: Enable detailed debugging output
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Initialize data structure to hold consolidated data by kid
    # If we allow duplicate keys, we'll store lists of values for each key
    if allow_duplicate_keys:
        consolidated_data = defaultdict(lambda: defaultdict(list))
    else:
        consolidated_data = defaultdict(dict)

    # Keep track of key collisions when using drv_name
    key_collisions = defaultdict(list)

    # List to count files and successful parses
    file_count = 0
    successful_signatures = 0

    # Check if input directory exists
    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist or is not a directory")
        return

    # Get list of files
    try:
        files = os.listdir(input_dir)
        print(f"Found {len(files)} files in input directory")
    except Exception as e:
        print(f"Error accessing input directory: {e}")
        return

    # Process each file in the input directory
    for filename in files:
        filepath = os.path.join(input_dir, filename)

        # Skip directories and non-JSON files
        if not os.path.isfile(filepath):
            if debug:
                print(f"Skipping {filename}: Not a file")
            continue

        # Consider all files as potential JSON even without .json extension
        file_count += 1

        if debug:
            print(f"Processing file: {filename}")

        try:
            with open(filepath, 'r') as f:
                file_content = f.read()

            if debug and len(file_content) < 200:
                print(f"File content: {file_content}")

            file_data = json.loads(file_content)

            # Extract signatures from the file
            signatures = file_data.get('signatures', [])

            if debug:
                print(f"Found {len(signatures)} signatures in {filename}")

            if not signatures:
                print(f"Warning: No signatures found in {filename}")

            # Process each signature
            for i, signature in enumerate(signatures):
                # Parse the JWT payload (without validation)
                # Assuming the JWT consists of header.payload.signature
                try:
                    parts = signature.split('.')
                    if len(parts) != 3:
                        print(f"Warning: Invalid JWT format in {filename}, signature #{i+1}")
                        continue

                    header_b64, payload_b64, signature_b64 = parts

                    # Padding for base64 decoding
                    def pad_base64(b64_str):
                        return b64_str + '=' * (4 - len(b64_str) % 4) if len(b64_str) % 4 else b64_str

                    # Extract the kid from the header
                    try:
                        padded_header = pad_base64(header_b64)
                        header_bytes = base64.urlsafe_b64decode(padded_header)
                        header_json = json.loads(header_bytes.decode('utf-8'))
                        kid = header_json.get('kid')
                        kid = kid.replace(":", "_") # sanitize kid

                        if debug:
                            print(f"Header: {header_json}")

                        if not kid:
                            print(f"Warning: No 'kid' found in header for file {filename}, signature #{i+1}")
                            continue

                    except Exception as e:
                        print(f"Error decoding header in {filename}, signature #{i+1}: {e}")
                        if debug:
                            print(f"Header base64: {header_b64}")
                        continue

                    # Decode the payload
                    try:
                        padded_payload = pad_base64(payload_b64)
                        payload_bytes = base64.urlsafe_b64decode(padded_payload)
                        payload_json = json.loads(payload_bytes.decode('utf-8'))

                        if debug:
                            print(f"First part of payload: {str(payload_json)[:100]}...")

                    except Exception as e:
                        print(f"Error decoding payload in {filename}, signature #{i+1}: {e}")
                        if debug:
                            print(f"Payload base64: {payload_b64[:50]}...")
                        continue

                    debug_json = payload_json['in']['debug']
                    # Note: aterm preimages are not JSON, they're aterm format
                    # So we don't try to parse them as JSON anymore

                    # Get the key field value from payload
                    key_value = None
                    drv_path = None

                    if key_field == 'in':
                        key_value = payload_json.get('in').get('rdrv_aterm_ca')
                    elif key_field == 'drv_name':
                        # Extract name from debug info (should be in debug_json directly)
                        key_value = debug_json.get('drv_name')
                    else:  # Default to drv_path
                        key_value = debug_json.get('rdrv_path')

                    if not key_value:
                        print(f"Warning: No '{key_field}' found in payload for file {filename}, signature #{i+1}")
                        continue

                    # Check for collisions when using drv_name
                    if key_field == 'drv_name' and not allow_duplicate_keys:
                        if kid in consolidated_data and key_value in consolidated_data[kid]:
                            # In regular mode, this is a dict
                            existing_drv_path = consolidated_data[kid][key_value].get('in').get('debug').get('rdrv_path')
                            if existing_drv_path != drv_path:
                                key_collisions[kid].append((key_value, existing_drv_path, drv_path))
                                if debug:
                                    print(f"Warning: Name collision for kid={kid}, name={key_value}")
                                    print(f"  Existing path: {existing_drv_path}")
                                    print(f"  New path: {drv_path}")

                    # Store all payload data
                    payload_copy = payload_json.copy()

                    # Add to the consolidated data
                    if allow_duplicate_keys:
                        consolidated_data[kid][key_value].append(payload_copy)
                    else:
                        consolidated_data[kid][key_value] = payload_copy

                    successful_signatures += 1

                    if debug:
                        print(f"Successfully processed signature with kid={kid}, key={key_value}")

                except Exception as e:
                    print(f"Error processing signature in file {filename}, signature #{i+1}: {e}")

        except Exception as e:
            print(f"Error processing file {filename}: {e}")

    # Check for name collisions if not allowing duplicates
    if not allow_duplicate_keys and key_field == 'drv_name' and key_collisions:
        print("Error: Found name collisions (multiple different derivations with the same name):")
        for kid, collisions in key_collisions.items():
            print(f"  Kid: {kid}")
            for name, path1, path2 in collisions:
                print(f"    Name: {name}")
                print(f"      Path 1: {path1}")
                print(f"      Path 2: {path2}")
        print("Aborting: Cannot proceed with ambiguous name mappings.")
        return

    # Summary
    print(f"Processed {file_count} files")
    print(f"Successfully extracted {successful_signatures} signatures")
    print(f"Found {len(consolidated_data)} unique kid values")

    if not consolidated_data:
        print("No data was successfully processed. Check the error messages above.")
        return

    # Write consolidated data to output files
    for kid, data in consolidated_data.items():
        output_filename = os.path.join(output_dir, f"{kid}.json")
        try:
            # For allow_duplicate_keys mode, we need to handle the nested structure
            if allow_duplicate_keys:
                # Convert the defaultdict(list) to a regular dict
                # If there's only one item in a list, extract it to maintain similar output
                # format for cases without duplicates
                formatted_data = {}
                for key, items in data.items():
                    if len(items) == 1:
                        formatted_data[key] = items[0]  # Extract single items
                    else:
                        formatted_data[key] = items     # Keep list for duplicates

                # Write the formatted data
                with open(output_filename, 'w') as f:
                    json.dump(formatted_data, f, indent=2)
            else:
                # Standard output for non-duplicate mode
                with open(output_filename, 'w') as f:
                    json.dump(data, f, indent=2)

            print(f"Created file {output_filename}")
        except Exception as e:
            print(f"Error writing output file {output_filename}: {e}")


def main():
    parser = argparse.ArgumentParser(description='Process JSON files and consolidate by kid')
    parser.add_argument('--input-dir', required=True, help='Directory containing input JSON files')
    parser.add_argument('--output-dir', required=True, help='Directory to save output JSON files')
    parser.add_argument('--key-field', choices=['drv_path', 'in', 'drv_name'], default='drv_path',
                        help='Field to use as keys in the output JSON (default: drv_path)')
    parser.add_argument('--allow-duplicate-keys', action='store_true', 
                        help='Allow duplicate keys in output. Only relevant when `--key_filed drv_path`')
    parser.add_argument('--debug', action='store_true', help='Enable detailed debugging output')

    args = parser.parse_args()

    process_json_files(args.input_dir, args.output_dir, args.key_field, args.allow_duplicate_keys, args.debug)


if __name__ == "__main__":
    main()
