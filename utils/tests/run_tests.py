#!/usr/bin/env python3
"""
Run all test utilities in the utils directory.
"""

import os
import subprocess
import sys


def run_test(test_file):
    """Run a test file and return success status."""
    print(f"\n{'=' * 60}")
    print(f"Running: {test_file}")
    print(f"{'=' * 60}")

    try:
        result = subprocess.run(
            [sys.executable, test_file],
            capture_output=False,
            text=True,
            cwd=os.path.dirname(test_file),
        )
        return result.returncode == 0
    except Exception as e:
        print(f"Error running {test_file}: {e}")
        return False


def main():
    """Run all available tests."""
    utils_dir = os.path.dirname(__file__)

    # List of test files to run
    test_files = [
        "test_smb_connectivity.py",
        "test_replay_connection.py",
        "test_simple_connectivity.py",
    ]

    print("SMB Replay System - Test Suite")
    print("=" * 60)

    results = {}

    for test_file in test_files:
        test_path = os.path.join(utils_dir, test_file)
        if os.path.exists(test_path):
            success = run_test(test_path)
            results[test_file] = success
        else:
            print(f"\nSkipping {test_file} (not found)")
            results[test_file] = None

    # Summary
    print(f"\n{'=' * 60}")
    print("TEST SUMMARY")
    print(f"{'=' * 60}")

    for test_file, result in results.items():
        if result is None:
            status = "SKIPPED"
        elif result:
            status = "✅ PASSED"
        else:
            status = "❌ FAILED"
        print(f"{test_file}: {status}")

    # Overall result
    passed = sum(1 for r in results.values() if r is True)
    total = sum(1 for r in results.values() if r is not None)

    print(f"\nOverall: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! SMB replay system is ready.")
    else:
        print("⚠️  Some tests failed. Check configuration and setup.")


if __name__ == "__main__":
    main()
