#!/usr/bin/env python3
"""
Test script to verify the SMB2 Replay System conversion from notebook to Python modules.
"""

import os
import sys
import traceback


def test_imports():
    """Test that all modules can be imported successfully."""
    print("Testing imports...")

    # Test individual module imports
    from smbreplay import config

    print("✓ config module imported")

    from smbreplay import constants

    print("✓ constants module imported")

    from smbreplay import tshark_processor

    print("✓ tshark_processor module imported")

    from smbreplay import ingestion

    print("✓ ingestion module imported")

    from smbreplay import session_manager

    print("✓ session_manager module imported")

    from smbreplay import replay

    print("✓ replay module imported")

    from smbreplay import main

    print("✓ main module imported")

    from smbreplay import utils

    print("✓ utils module imported")

    # Test package-level imports
    from smbreplay import SMB2ReplaySystem

    print("✓ SMB2ReplaySystem imported")

    from smbreplay import get_config, get_logger

    print("✓ Configuration functions imported")


def test_configuration():
    """Test configuration system."""
    print("\nTesting configuration...")

    from smbreplay import get_config, get_logger, set_verbosity

    # Test configuration manager
    config = get_config()
    print(f"✓ Configuration manager created: {type(config)}")

    # Test logger
    logger = get_logger()
    print(f"✓ Logger created: {type(logger)}")
    logger.info("Test log message")

    # Test verbosity setting
    set_verbosity(1)
    print("✓ Verbosity set successfully")


def test_constants():
    """Test constants and mappings."""
    print("\nTesting constants...")

    from smbreplay import FIELD_MAPPINGS, FSCTL_CONSTANTS, SMB2_OP_NAME_DESC
    from smbreplay.constants import check_tshark_availability

    # Test constants
    print(f"✓ SMB2_OP_NAME_DESC loaded: {len(SMB2_OP_NAME_DESC)} commands")
    print(f"✓ FSCTL_CONSTANTS loaded: {len(FSCTL_CONSTANTS)} constants")
    print(f"✓ FIELD_MAPPINGS loaded: {len(FIELD_MAPPINGS)} mappings")

    # Test tshark availability check
    tshark_available = check_tshark_availability()
    print(f"✓ Tshark availability check: {tshark_available}")


def test_system_creation():
    """Test system creation and setup."""
    print("\nTesting system creation...")

    from smbreplay import SMB2ReplaySystem

    # Create system instance
    system = SMB2ReplaySystem()
    print(f"✓ System created: {type(system)}")

    # Test setup
    setup_result = system.setup_system()
    print(f"✓ System setup: {setup_result}")

    # Test system info
    info = system.get_system_info()
    print(f"✓ System info retrieved: {len(info)} fields")


def test_session_manager():
    """Test session manager functionality."""
    print("\nTesting session manager...")

    from smbreplay import SessionManager, get_session_manager

    # Test session manager creation
    session_mgr = get_session_manager()
    print(f"✓ Session manager created: {type(session_mgr)}")

    # Test session manager methods (without actual data)
    summary = session_mgr.get_session_summary()
    print(f"✓ Session summary retrieved: {len(summary)} fields")


def test_replay_functionality():
    """Test replay functionality."""
    print("\nTesting replay functionality...")

    from smbreplay import get_supported_commands, validate_operations

    # Test supported commands
    supported = get_supported_commands()
    print(f"✓ Supported commands: {len(supported)} commands")

    # Test operation validation (empty list)
    validation = validate_operations([])
    print(f"✓ Operation validation: {validation['valid']}")


def test_utilities():
    """Test utility functions."""
    print("\nTesting utilities...")

    from smbreplay import Timer, format_bytes, format_duration

    # Test formatters
    size_str = format_bytes(1024 * 1024)
    print(f"✓ Format bytes: {size_str}")

    duration_str = format_duration(125.5)
    print(f"✓ Format duration: {duration_str}")

    # Test timer
    with Timer("Test operation") as timer:
        import time

        time.sleep(0.1)
    print(f"✓ Timer: {timer}")


def test_command_line():
    """Test command line interface."""
    print("\nTesting command line interface...")

    from smbreplay.main import create_cli_parser

    # Test CLI parser creation
    parser = create_cli_parser()
    print(f"✓ CLI parser created: {type(parser)}")

    # Test help generation
    help_text = parser.format_help()
    print(f"✓ Help text generated: {len(help_text)} characters")


def main():
    """Run all tests."""
    print("SMB2 Replay System - Conversion Test")
    print("=" * 50)

    tests = [
        test_imports,
        test_configuration,
        test_constants,
        test_system_creation,
        test_session_manager,
        test_replay_functionality,
        test_utilities,
        test_command_line,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test {test.__name__} crashed: {e}")
            failed += 1

    print("\n" + "=" * 50)
    print(f"Test Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("🎉 All tests passed! The conversion was successful.")
        return 0
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
