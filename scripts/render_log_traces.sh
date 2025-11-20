#!/usr/bin/env bash
set -euo pipefail

# Script to convert Python log files to PNG sequence diagrams
# Usage: ./render_log_traces.sh <search_directory> <output_directory>
#
# This script:
# 1. Finds all python_harness.log files under the given search directory
# 2. Converts each to Mermaid format using log_to_mermaid.py
# 3. Renders the Mermaid diagram to PNG using mmdc (mermaid-cli)
# 4. Outputs all PNG files to the specified output directory (no subdirectories)
#
# Requirements:
# - Python 3 with log_to_mermaid.py in the same directory
# - mmdc (mermaid-cli): npm install -g @mermaid-js/mermaid-cli

# Get the directories from arguments
if [ $# -lt 2 ]; then
    echo "Usage: $0 <search_directory> <output_directory>" >&2
    echo "Example: $0 test-results out" >&2
    exit 1
fi

SEARCH_DIR="$1"
OUTPUT_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_TO_MERMAID="${SCRIPT_DIR}/log_to_mermaid.py"

# Check if log_to_mermaid.py exists
if [ ! -f "$LOG_TO_MERMAID" ]; then
    echo "Error: log_to_mermaid.py not found at ${LOG_TO_MERMAID}" >&2
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

# Find all python_harness.log files
echo "Searching for python_harness.log files in ${SEARCH_DIR}..."
log_files=$(find "$SEARCH_DIR" -type f -name "python_harness.log")

if [ -z "$log_files" ]; then
    echo "No python_harness.log files found in ${SEARCH_DIR}" >&2
    exit 0
fi

# Process each log file
count=0
while IFS= read -r log_file; do
    echo "Processing: ${log_file}"
    
    # Extract the run directory name from the path
    # Expected pattern: .../test-results/run_XXXX/python_harness.log
    
    # Get the directory containing the log file
    log_dir=$(dirname "$log_file")
    
    # Extract run name (directory name, e.g., run_0001)
    run_name=$(basename "$log_dir")
    
    # Construct output filename: <run_name>-trace.png
    output_name="${run_name}-trace"
    mmd_file="${TEMP_DIR}/${output_name}.mmd"
    png_file="${OUTPUT_DIR}/${output_name}.png"
    
    # Convert log to Mermaid
    if [ -f "$png_file" ]; then
        echo "  → Skipping, output already exists: ${png_file}"
        continue
    fi
    
    if python3 "$LOG_TO_MERMAID" "$log_file" "$mmd_file" 2>/dev/null; then
        echo "  ✓ Created Mermaid diagram (temp)"
        
        # Verify the mermaid file was actually created
        if [ ! -f "$mmd_file" ]; then
            echo "  ✗ Mermaid file was not created: ${mmd_file}" >&2
            continue
        fi
        
        # Render Mermaid to PNG with neutral theme
        echo "Generating single mermaid chart"
        
        # Determine if we're running in GitHub Actions CI
        if [ -n "${GITHUB_ACTIONS:-}" ]; then
            # In GitHub Actions, use --no-sandbox for Chromium
            echo "  Command: mmdc -i $mmd_file -o $png_file -t neutral -b transparent (with --no-sandbox for CI)"
            mmdc_result=$(mmdc -i "$mmd_file" -o "$png_file" -t neutral -b transparent --puppeteerConfigFile <(echo '{"args":["--no-sandbox","--disable-setuid-sandbox"]}') 2>&1)
        else
            # Locally, use sandbox (default behavior)
            echo "  Command: mmdc -i $mmd_file -o $png_file -t neutral -b transparent"
            mmdc_result=$(mmdc -i "$mmd_file" -o "$png_file" -t neutral -b transparent 2>&1)
        fi
        
        mmdc_exit=$?
        
        if [ $mmdc_exit -eq 0 ]; then
            # Verify the PNG was created
            if [ -f "$png_file" ]; then
                echo "  ✓ Rendered PNG: ${png_file}"
                count=$((count + 1))
            else
                echo "  ✗ PNG file was not created: ${png_file}" >&2
                echo "$mmdc_result" >&2
            fi
        else
            echo "  ✗ Failed to render PNG for ${log_file}" >&2
            echo "$mmdc_result" >&2
        fi
    else
        echo "  ✗ Failed to convert ${log_file} to Mermaid" >&2
    fi
    
    echo ""
done <<< "$log_files"

echo "Processed ${count} log files successfully."
