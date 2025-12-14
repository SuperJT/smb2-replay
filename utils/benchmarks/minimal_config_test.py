#!/usr/bin/env python3
"""
Minimal test to isolate config import slowness.
"""

import os
import sys
import time

# Add the smbreplay package to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
package_dir = os.path.join(script_dir, "..", "..", "smbreplay_package")
sys.path.insert(0, package_dir)

print("=== Minimal Config Import Test ===")

# Test the actual problematic import
start = time.time()
try:
    print("Starting import...")
    import smbreplay.config

    end = time.time()
    print(f"Import smbreplay.config: {end - start:.3f}s")

    # Test getting the config
    start = time.time()
    config = smbreplay.config.get_config()
    end = time.time()
    print(f"get_config(): {end - start:.3f}s")

except Exception as e:
    end = time.time()
    print(f"Import failed after {end - start:.3f}s: {e}")
    import traceback

    traceback.print_exc()

print("\n=== Test Complete ===")
