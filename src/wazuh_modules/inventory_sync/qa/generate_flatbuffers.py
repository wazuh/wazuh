#!/usr/bin/env python3
"""
FlatBuffers Generator for Inventory Sync Testing
This script generates Python FlatBuffers classes from the inventorySync.fbs schema.
"""

import os
import subprocess
import sys
from pathlib import Path


def find_flatc_executable():
    """Find the flatc executable in the system."""
    # Try common locations
    common_paths = [
        "/usr/local/bin/flatc",
        "/usr/bin/flatc",
        "flatc"  # Try PATH
    ]

    # Also look in the wazuh source tree (built from external deps)
    script_dir = Path(__file__).resolve().parent
    src_root = script_dir.parent.parent.parent  # .../src
    common_paths.insert(0, str(src_root / "external" / "flatbuffers" / "build" / "flatc"))

    for path in common_paths:
        try:
            result = subprocess.run([path, "--version"], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=5)
            if result.returncode == 0:
                return path
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    
    return None


def main():
    """Main function to generate FlatBuffers classes.

    Idempotent: if `generated/Wazuh/SyncSchema/Message.py` already exists and
    is newer than the schema file, returns True immediately without running
    flatc and without printing the verbose banner. This is the hot path —
    callers (e.g. FlatBuffersManager) invoke main() on every benchmark agent
    instantiation, so reaching flatc unnecessarily costs subprocess startup
    plus ~25 lines of stdout per call.
    """
    # Get current directory and schema path
    current_dir = Path(__file__).resolve().parent
    schema_file = current_dir.parent.parent.parent / "shared_modules" / "utils" / "flatbuffers" / "schemas" / "inventorySync.fbs"
    generated_dir = current_dir / "generated"

    # Check if schema file exists
    if not schema_file.exists():
        print(f"❌ Schema file not found: {schema_file}")
        return False

    # Idempotency check: use the LAST file flatc emits as the witness so we
    # don't false-positive when a previous run was interrupted mid-write.
    witness = generated_dir / "Wazuh" / "SyncSchema" / "Message.py"
    if witness.exists() and witness.stat().st_mtime >= schema_file.stat().st_mtime:
        print("✅ FlatBuffers classes up to date — skipping regeneration.")
        return True

    print("🔧 Generating FlatBuffers classes for inventory sync...")

    # Find flatc executable
    flatc_path = find_flatc_executable()
    if not flatc_path:
        print("❌ flatc executable not found. Please install FlatBuffers.")
        print("   On Ubuntu/Debian: sudo apt-get install flatbuffers-compiler")
        print("   On macOS: brew install flatbuffers")
        return False

    print(f"✅ Using flatc: {flatc_path}")
    print(f"📄 Schema file: {schema_file}")

    # Create generated directory
    generated_dir.mkdir(exist_ok=True)
    
    # Generate Python classes
    try:
        cmd = [
            flatc_path,
            "--python",
            "--gen-object-api",
            "-o", str(generated_dir),
            str(schema_file)
        ]
        
        print(f"🚀 Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ FlatBuffers classes generated successfully!")
            
            # Create __init__.py files to make it a proper Python package
            init_files = [
                generated_dir / "__init__.py",
                generated_dir / "Wazuh" / "__init__.py",
                generated_dir / "Wazuh" / "SyncSchema" / "__init__.py"
            ]
            
            for init_file in init_files:
                init_file.parent.mkdir(parents=True, exist_ok=True)
                if not init_file.exists():
                    init_file.touch()
            
            # List generated files
            print("📁 Generated files:")
            for root, dirs, files in os.walk(generated_dir):
                for file in files:
                    if file.endswith('.py'):
                        file_path = Path(root) / file
                        rel_path = file_path.relative_to(generated_dir)
                        print(f"   - {rel_path}")
            
            return True
        else:
            print(f"❌ flatc failed with return code {result.returncode}")
            print(f"stdout: {result.stdout}")
            print(f"stderr: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ flatc command timed out")
        return False
    except Exception as e:
        print(f"❌ Error running flatc: {e}")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
