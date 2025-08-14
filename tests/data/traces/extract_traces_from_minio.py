#!/usr/bin/env python3
"""
Extract JSON trace data from MinIO xl.meta files.

MinIO stores objects as directories with xl.meta files containing the actual data.
This script extracts the JSON data from these files.
"""

import os
import sys
import json
import re
import subprocess
from pathlib import Path

def extract_json_from_xl_meta(xl_meta_path):
    """Extract JSON data from a MinIO xl.meta file."""
    try:
        with open(xl_meta_path, 'rb') as f:
            content = f.read()
        
        # Convert to string, handling non-UTF8 bytes
        content_str = content.decode('utf-8', errors='ignore')
        
        # Look for JSON structure in the file
        # The JSON typically starts with {"signatures": 
        json_match = re.search(r'(\{"signatures":\s*\[[^\0]+\]\})', content_str)
        
        if json_match:
            json_str = json_match.group(1)
            # Validate it's proper JSON
            json_data = json.loads(json_str)
            return json_data
        else:
            # Try to find JSON using a different pattern
            # Sometimes the JSON might be embedded differently
            start_idx = content_str.find('{"signatures":')
            if start_idx != -1:
                # Find the end of the JSON
                bracket_count = 0
                end_idx = start_idx
                for i in range(start_idx, len(content_str)):
                    if content_str[i] == '{':
                        bracket_count += 1
                    elif content_str[i] == '}':
                        bracket_count -= 1
                        if bracket_count == 0:
                            end_idx = i + 1
                            break
                
                if end_idx > start_idx:
                    json_str = content_str[start_idx:end_idx]
                    json_data = json.loads(json_str)
                    return json_data
        
        print(f"Warning: No JSON found in {xl_meta_path}")
        return None
        
    except Exception as e:
        print(f"Error processing {xl_meta_path}: {e}")
        return None

def process_minio_traces(input_dir, output_dir):
    """Process all xl.meta files in the MinIO traces directory."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    
    if not input_path.exists():
        print(f"Error: Input directory {input_dir} does not exist")
        sys.exit(1)
    
    output_path.mkdir(parents=True, exist_ok=True)
    
    processed = 0
    errors = 0
    
    # Process each directory in traces/
    for trace_dir in input_path.iterdir():
        if not trace_dir.is_dir():
            continue
            
        xl_meta_file = trace_dir / "xl.meta"
        if not xl_meta_file.exists():
            print(f"Warning: No xl.meta file in {trace_dir}")
            continue
        
        # Extract JSON from xl.meta
        json_data = extract_json_from_xl_meta(xl_meta_file)
        
        if json_data:
            # Save to output directory with the directory name as filename
            output_file = output_path / trace_dir.name
            
            # Use jq to format the JSON nicely
            json_str = json.dumps(json_data)
            result = subprocess.run(
                ['jq', '.'],
                input=json_str,
                capture_output=True,
                text=True,
                check=True
            )
            
            with open(output_file, 'w') as f:
                f.write(result.stdout)
                    
            print(f"Extracted: {trace_dir.name} -> {output_file}")
            processed += 1
        else:
            errors += 1
    
    print(f"\nProcessed: {processed} files")
    print(f"Errors: {errors} files")

def main():
    if len(sys.argv) != 3:
        print("Usage: extract_traces_from_minio.py <input_dir> <output_dir>")
        print("Example: extract_traces_from_minio.py result/data/binary-cache/traces /tmp/extracted_traces")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    
    process_minio_traces(input_dir, output_dir)

if __name__ == "__main__":
    main()