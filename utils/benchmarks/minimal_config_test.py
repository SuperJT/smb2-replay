#!/usr/bin/env python3
"""
Minimal test to isolate config import slowness.
"""

import sys
import os
import time

# Add the current directory to the Python path
sys.path.insert(0, '/home/jtownsen/bin/smbreplay/smbreplay_package')

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
