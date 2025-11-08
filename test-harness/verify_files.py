#!/usr/bin/env python3
"""
Verify that test files match the sizes specified in MC2_tftp.tla.

Claude Sonnet 4.5, 2025
"""

import sys
from pathlib import Path

# File sizes from MC2_tftp.tla
EXPECTED_SIZES = {
    "file1": 1024,
    "file2": 2099,
    "file3": 12345,
}

def verify_files(files_dir: Path) -> bool:
    """
    Verify that files exist and have the correct sizes.
    
    Args:
        files_dir: Directory containing test files
        
    Returns:
        True if all files are correct, False otherwise
    """
    all_good = True
    
    for filename, expected_size in EXPECTED_SIZES.items():
        file_path = files_dir / filename
        
        if not file_path.exists():
            print(f"❌ {filename}: File not found")
            all_good = False
            continue
        
        actual_size = file_path.stat().st_size
        
        if actual_size == expected_size:
            print(f"✅ {filename}: {actual_size} bytes (correct)")
        else:
            print(f"❌ {filename}: {actual_size} bytes (expected {expected_size})")
            all_good = False
    
    return all_good

def create_files(files_dir: Path) -> bool:
    """
    Create test files with the correct sizes.
    
    Args:
        files_dir: Directory to create files in
        
    Returns:
        True if successful
    """
    files_dir.mkdir(parents=True, exist_ok=True)
    
    for filename, size in EXPECTED_SIZES.items():
        file_path = files_dir / filename
        
        # Create file with random data
        with open(file_path, 'wb') as f:
            # Use repeating pattern for predictability
            pattern = f"This is test file {filename}.\n".encode('utf-8')
            written = 0
            while written < size:
                chunk_size = min(len(pattern), size - written)
                f.write(pattern[:chunk_size])
                written += chunk_size
        
        print(f"Created {filename}: {size} bytes")
    
    return True

def main():
    script_dir = Path(__file__).parent
    files_dir = script_dir / "files"
    
    if len(sys.argv) > 1 and sys.argv[1] == "--create":
        print("Creating test files...")
        create_files(files_dir)
    else:
        print("Verifying test files...")
        if not files_dir.exists():
            print(f"\nError: {files_dir} does not exist")
            print("Run with --create to create the files")
            sys.exit(1)
        
        if verify_files(files_dir):
            print("\n✅ All files are correct")
            sys.exit(0)
        else:
            print("\n❌ Some files are incorrect")
            print("Run with --create to recreate the files")
            sys.exit(1)

if __name__ == "__main__":
    main()
