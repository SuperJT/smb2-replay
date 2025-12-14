#!/usr/bin/env python3
"""
Detailed benchmark to isolate the config module slowness.
"""

import time


def benchmark_step(description, func):
    """Benchmark a single step."""
    start_time = time.time()
    try:
        result = func()
        end_time = time.time()
        print(f"{description}: {end_time - start_time:.3f}s")
        return result
    except Exception as e:
        end_time = time.time()
        print(f"{description}: {end_time - start_time:.3f}s (ERROR: {e})")
        return None


print("=== Config Module Detailed Benchmark ===")

# Test basic imports
benchmark_step("1. Import os", lambda: __import__("os"))
benchmark_step("2. Import sys", lambda: __import__("sys"))
benchmark_step("3. Import pickle", lambda: __import__("pickle"))
benchmark_step("4. Import logging", lambda: __import__("logging"))
benchmark_step("5. Import typing", lambda: __import__("typing"))

# Test os.path.expanduser
import os

benchmark_step("6. os.path.expanduser('~')", lambda: os.path.expanduser("~"))
benchmark_step(
    "7. os.path.expanduser('~/cases')", lambda: os.path.expanduser("~/cases")
)
benchmark_step(
    "8. os.path.expanduser('~/.config/smbreplay')",
    lambda: os.path.expanduser("~/.config/smbreplay"),
)

# Test file system operations
benchmark_step(
    "9. os.path.exists('~/.config')",
    lambda: os.path.exists(os.path.expanduser("~/.config")),
)
benchmark_step(
    "10. os.path.exists('~/cases')",
    lambda: os.path.exists(os.path.expanduser("~/cases")),
)

# Test the actual config module import
benchmark_step("11. Import smbreplay.config", lambda: __import__("smbreplay.config"))

print("\n=== Config Module Import Analysis ===")

# Import individual components
config_module = __import__("smbreplay.config")
config_obj = config_module.config

# Test ConfigManager class creation
benchmark_step("12. ConfigManager class import", lambda: config_obj.ConfigManager)

# Test default values
benchmark_step("13. DEFAULT_PCAP_CONFIG", lambda: config_obj.DEFAULT_PCAP_CONFIG)
benchmark_step("14. DEFAULT_REPLAY_CONFIG", lambda: config_obj.DEFAULT_REPLAY_CONFIG)
benchmark_step("15. VERBOSITY_TO_LOGGING", lambda: config_obj.VERBOSITY_TO_LOGGING)

# Test ConfigManager instantiation
benchmark_step("16. ConfigManager()", lambda: config_obj.ConfigManager())

print("\n=== Benchmark Complete ===")
