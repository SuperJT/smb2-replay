#!/usr/bin/env python3
"""
SMBReplay File Testing Script

This script provides basic testing capabilities for formatted files.
It can test imports, syntax, and basic functionality.

Usage:
    python test_formatted_file.py <file_path> [--import-test] [--syntax-test] [--basic-test]
"""

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from typing import Optional


def test_syntax(file_path: str) -> bool:
    """Test if the file has valid Python syntax."""
    try:
        with open(file_path, 'r') as f:
            compile(f.read(), file_path, 'exec')
        print(f"✅ Syntax test passed: {file_path}")
        return True
    except SyntaxError as e:
        print(f"❌ Syntax error in {file_path}: {e}")
        return False
    except Exception as e:
        print(f"❌ Error checking syntax: {e}")
        return False


def test_import(file_path: str) -> bool:
    """Test if the file can be imported without errors."""
    try:
        # Get the module name from the file path
        file_path_obj = Path(file_path)
        
        # Handle __init__.py files
        if file_path_obj.name == "__init__.py":
            module_path = file_path_obj.parent
        else:
            module_path = file_path_obj.parent / file_path_obj.stem
        
        # Convert to module name
        module_name = str(module_path).replace("/", ".").replace("\\", ".")
        
        # Remove smbreplay_package prefix if present
        if module_name.startswith("smbreplay_package."):
            module_name = module_name[len("smbreplay_package."):]
        
        # Test import
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            print(f"❌ Could not create spec for: {module_name}")
            return False
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        print(f"✅ Import test passed: {module_name}")
        return True
        
    except ImportError as e:
        print(f"❌ Import error for {file_path}: {e}")
        return False
    except Exception as e:
        print(f"❌ Import test error: {e}")
        return False


def test_basic_functionality(file_path: str) -> bool:
    """Test basic functionality of the file."""
    try:
        # Get the module name
        file_path_obj = Path(file_path)
        if file_path_obj.name == "__init__.py":
            module_path = file_path_obj.parent
        else:
            module_path = file_path_obj.parent / file_path_obj.stem
        
        module_name = str(module_path).replace("/", ".").replace("\\", ".")
        if module_name.startswith("smbreplay_package."):
            module_name = module_name[len("smbreplay_package."):]
        
        # Import the module
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        if spec is None or spec.loader is None:
            return False
        
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Basic functionality tests based on module type
        if hasattr(module, 'get_config'):
            # Config module
            try:
                config = module.get_config()
                print(f"✅ Config module test passed: get_config() returned {type(config)}")
            except Exception as e:
                print(f"⚠️  Config module test warning: {e}")
        
        elif hasattr(module, 'get_logger'):
            # Logger module
            try:
                logger = module.get_logger()
                print(f"✅ Logger module test passed: get_logger() returned {type(logger)}")
            except Exception as e:
                print(f"⚠️  Logger module test warning: {e}")
        
        elif hasattr(module, 'handle_negotiate'):
            # Handler module
            print(f"✅ Handler module test passed: handle_negotiate function found")
        
        elif hasattr(module, 'main'):
            # Main module
            print(f"✅ Main module test passed: main function found")
        
        else:
            # Generic module
            print(f"✅ Basic functionality test passed: module loaded successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False


def run_flake8(file_path: str) -> bool:
    """Run flake8 on the file to check for issues."""
    try:
        import subprocess
        result = subprocess.run(
            ["flake8", file_path],
            capture_output=True,
            text=True,
            check=False
        )
        
        if result.returncode == 0:
            print(f"✅ flake8 passed: {file_path}")
            return True
        else:
            print(f"⚠️  flake8 found issues in {file_path}:")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"❌ flake8 test error: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Test a formatted Python file"
    )
    parser.add_argument(
        "file_path",
        help="Path to the Python file to test"
    )
    parser.add_argument(
        "--syntax-test",
        action="store_true",
        help="Test Python syntax"
    )
    parser.add_argument(
        "--import-test",
        action="store_true",
        help="Test module import"
    )
    parser.add_argument(
        "--basic-test",
        action="store_true",
        help="Test basic functionality"
    )
    parser.add_argument(
        "--flake8-test",
        action="store_true",
        help="Run flake8 checks"
    )
    parser.add_argument(
        "--all-tests",
        action="store_true",
        help="Run all tests"
    )
    
    args = parser.parse_args()
    
    file_path = args.file_path
    
    # Validate file exists
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    if not file_path.endswith('.py'):
        print(f"❌ Not a Python file: {file_path}")
        sys.exit(1)
    
    print(f"🧪 Testing file: {file_path}")
    print(f"📊 File size: {os.path.getsize(file_path)} bytes")
    
    # Determine which tests to run
    run_syntax = args.syntax_test or args.all_tests
    run_import = args.import_test or args.all_tests
    run_basic = args.basic_test or args.all_tests
    run_flake8_test = args.flake8_test or args.all_tests
    
    # If no specific tests requested, run all
    if not any([run_syntax, run_import, run_basic, run_flake8_test]):
        run_syntax = run_import = run_basic = run_flake8_test = True
    
    results = {
        "syntax": False,
        "import": False,
        "basic": False,
        "flake8": False
    }
    
    # Run tests
    if run_syntax:
        print("\n🔍 Running syntax test...")
        results["syntax"] = test_syntax(file_path)
    
    if run_import:
        print("\n📦 Running import test...")
        results["import"] = test_import(file_path)
    
    if run_basic:
        print("\n⚙️  Running basic functionality test...")
        results["basic"] = test_basic_functionality(file_path)
    
    if run_flake8_test:
        print("\n🔍 Running flake8 test...")
        results["flake8"] = run_flake8(file_path)
    
    # Summary
    print(f"\n{'='*50}")
    print("📋 TEST SUMMARY")
    print(f"{'='*50}")
    print(f"File: {file_path}")
    print(f"Syntax test: {'✅ Passed' if results['syntax'] else '❌ Failed'}")
    print(f"Import test: {'✅ Passed' if results['import'] else '❌ Failed'}")
    print(f"Basic test: {'✅ Passed' if results['basic'] else '❌ Failed'}")
    print(f"flake8 test: {'✅ Passed' if results['flake8'] else '❌ Failed'}")
    
    all_passed = all(results.values())
    print(f"\nOverall result: {'🎉 SUCCESS' if all_passed else '❌ FAILED'}")
    
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main() 