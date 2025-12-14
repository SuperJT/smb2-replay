#!/usr/bin/env python3
"""
Test to isolate the exact cause of the config import delay.
"""

import importlib.util
import os
import sys
import time

# Add the smbreplay package to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
package_dir = os.path.join(script_dir, "..", "..", "smbreplay_package")
sys.path.insert(0, package_dir)

print("=== Import Analysis ===")

# Step 1: Check if it's a sys.path issue
print("1. Testing sys.path...")
for i, path in enumerate(sys.path):
    start = time.time()
    exists = os.path.exists(path)
    end = time.time()
    if end - start > 0.1:  # Only show slow paths
        print(
            f"   Path {i}: {path} - {end - start:.3f}s ({'exists' if exists else 'missing'})"
        )

# Step 2: Try to import the config module directly
print("\n2. Testing config module import...")
start = time.time()
spec = importlib.util.find_spec("smbreplay.config")
end = time.time()
print(f"   find_spec: {end - start:.3f}s")

if spec:
    print(f"   Module found at: {spec.origin}")
    start = time.time()
    module = importlib.util.module_from_spec(spec)
    end = time.time()
    print(f"   module_from_spec: {end - start:.3f}s")

    if spec.loader is not None:
        start = time.time()
        spec.loader.exec_module(module)
        end = time.time()
        print(f"   exec_module: {end - start:.3f}s")
    else:
        print("   Loader is None, cannot exec_module!")
else:
    print("   Module not found!")

# Step 3: Check if it's the file itself
print("\n3. Testing file operations...")
config_path = os.path.join(package_dir, "smbreplay", "config.py")
start = time.time()
exists = os.path.exists(config_path)
end = time.time()
print(f"   os.path.exists: {end - start:.3f}s ({'exists' if exists else 'missing'})")

if exists:
    start = time.time()
    with open(config_path) as f:
        content = f.read()
    end = time.time()
    print(f"   file read: {end - start:.3f}s ({len(content)} chars)")

print("\n=== Analysis Complete ===")
