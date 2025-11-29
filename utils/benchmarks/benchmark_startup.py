#!/usr/bin/env python3
"""
Benchmark script to identify startup performance bottlenecks
"""
import time
import sys
import os

def benchmark_step(name, func):
    """Benchmark a single step"""
    start = time.time()
    result = func()
    end = time.time()
    print(f"{name}: {end - start:.3f}s")
    return result

def benchmark_import(module_name):
    """Benchmark module import"""
    start = time.time()
    __import__(module_name)
    end = time.time()
    print(f"Import {module_name}: {end - start:.3f}s")

def main():
    print("=== SMB Replay Startup Benchmark ===")
    
    # Step 1: Basic imports
    print("\n1. Basic imports:")
    benchmark_import("sys")
    benchmark_import("os")
    benchmark_import("argparse")
    
    # Step 2: SMB replay imports
    print("\n2. SMB replay imports:")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    package_dir = os.path.join(script_dir, '..', '..', 'smbreplay_package')
    sys.path.insert(0, package_dir)
    
    benchmark_import("smbreplay.config")
    
    # Step 3: Config system
    print("\n3. Config system:")
    def get_config():
        from smbreplay.config import get_config
        return get_config()
    
    config = benchmark_step("get_config()", get_config)
    
    # Step 4: Logger
    print("\n4. Logger:")
    def get_logger():
        from smbreplay.config import get_logger
        return get_logger()
    
    logger = benchmark_step("get_logger()", get_logger)
    
    # Step 5: SMB2ReplaySystem creation
    print("\n5. SMB2ReplaySystem creation:")
    def create_system():
        from smbreplay.main import SMB2ReplaySystem
        return SMB2ReplaySystem()
    
    system = benchmark_step("SMB2ReplaySystem()", create_system)
    
    # Step 6: Heavy imports (what we're trying to avoid)
    print("\n6. Heavy imports (lazy):")
    benchmark_import("pandas")
    
    print("\n=== Benchmark Complete ===")

if __name__ == "__main__":
    main()
