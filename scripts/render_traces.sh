#!/usr/bin/env bash
set -euo pipefail

# Script to convert ITF JSON traces to PNG sequence diagrams
# Usage: ./render_traces.sh <search_directory> <output_directory>
#
# This script:
# 1. Finds all trace.json files under the given search directory
# 2. Converts each to Mermaid format using itf_to_mermaid.py
# 3. Renders the Mermaid diagram to PNG using mmdc (mermaid-cli)
# 4. Outputs all PNG files to the specified output directory (no subdirectories)
#
# Requirements:
# - Python 3 with itf_to_mermaid.py in the same directory
# - mmdc (mermaid-cli): npm install -g @mermaid-js/mermaid-cli

# Get the directories from arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <search_directory> <output_directory>" >&2
    echo "Example: $0 corpus out" >&2
    exit 1
fi

SEARCH_DIR="$1"
OUTPUT_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ITF_TO_MERMAID="${SCRIPT_DIR}/itf_to_mermaid.py"

# Check if itf_to_mermaid.py exists
if [ ! -f "$ITF_TO_MERMAID" ]; then
    echo "Error: itf_to_mermaid.py not found at ${ITF_TO_MERMAID}" >&2
    exit 1
fi

# Check if mmdc is available
if ! command -v mmdc &> /dev/null; then
    echo "Error: mmdc (mermaid-cli) not found. Install with: npm install -g @mermaid-js/mermaid-cli" >&2
    exit 1
fi

# Check if the search directory exists
if [ ! -d "$SEARCH_DIR" ]; then
    echo "Error: Directory ${SEARCH_DIR} does not exist" >&2
    exit 1
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Create temporary directory for intermediate files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Find all trace.json files
echo "Searching for trace.json files in ${SEARCH_DIR}..."
trace_files=$(find "$SEARCH_DIR" -type f -name "trace.json")

if [ -z "$trace_files" ]; then
    echo "No trace.json files found in ${SEARCH_DIR}" >&2
    exit 0
fi

# Process each trace file
count=0
while IFS= read -r trace_file; do
    echo "Processing: ${trace_file}"
    
    # Extract the entry hash and view hash from the path
    # Expected pattern: .../corpus/queue/<entry_hash>/<view_hash>.view/trace.json
    
    # Get the directory containing trace.json
    trace_dir=$(dirname "$trace_file")
    
    # Extract view hash (directory name without .view suffix)
    view_dir=$(basename "$trace_dir")
    view_hash="${view_dir%.view}"
    
    # Extract entry hash (parent directory name)
    entry_dir=$(dirname "$trace_dir")
    entry_hash=$(basename "$entry_dir")
    
    # Construct output filename: <entry_hash>-<view_hash>-trace.png
    output_name="${entry_hash}-${view_hash}-trace"
    mmd_file="${TEMP_DIR}/${output_name}.mmd"
    pdf_file="${OUTPUT_DIR}/${output_name}.pdf"
    
    # Convert ITF JSON to Mermaid
    if [ -f "$pdf_file" ]; then
        echo "  → Skipping, output already exists: ${pdf_file}"
        continue;
    fi
    if python3 "$ITF_TO_MERMAID" "$trace_file" "$mmd_file"; then
        echo "  ✓ Created Mermaid diagram (temp)"
        
        # Render Mermaid to PNG with transparent background
        if mmdc -i "$mmd_file" -o "$pdf_file" -t neutral; then
            echo "  ✓ Rendered PNG: ${pdf_file}"
            count=$((count + 1))
        else
            echo "  ✗ Failed to render PNG for ${trace_file}" >&2
        fi
    else
        echo "  ✗ Failed to convert ${trace_file} to Mermaid" >&2
    fi
    
    echo ""
done <<< "$trace_files"

echo "Processed ${count} trace files successfully."
