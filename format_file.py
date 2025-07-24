#!/usr/bin/env python3
"""
SMBReplay File Formatting Script

This script formats individual Python files with backup and testing capabilities.
It ensures that formatting doesn't break functionality by creating backups
and running basic tests after formatting.

Usage:
    python format_file.py <file_path> [--backup] [--test] [--dry-run]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional, Tuple


def run_command(cmd: list, capture_output: bool = True) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)


def create_backup(file_path: str) -> Optional[str]:
    """Create a backup of the file before formatting."""
    try:
        backup_path = f"{file_path}.backup"
        shutil.copy2(file_path, backup_path)
        print(f"✅ Created backup: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to create backup: {e}")
        return None


def restore_backup(file_path: str, backup_path: str) -> bool:
    """Restore file from backup."""
    try:
        shutil.copy2(backup_path, file_path)
        print(f"✅ Restored from backup: {backup_path}")
        return True
    except Exception as e:
        print(f"❌ Failed to restore backup: {e}")
        return False


def check_syntax(file_path: str) -> bool:
    """Check if the file has valid Python syntax."""
    try:
        with open(file_path, 'r') as f:
            compile(f.read(), file_path, 'exec')
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
        cmd = [sys.executable, "-c", f"import {module_name}"]
        exit_code, stdout, stderr = run_command(cmd)
        
        if exit_code == 0:
            print(f"✅ Import test passed: {module_name}")
            return True
        else:
            print(f"❌ Import test failed: {module_name}")
            print(f"   Error: {stderr}")
            return False
    except Exception as e:
        print(f"❌ Import test error: {e}")
        return False


def format_file(file_path: str, dry_run: bool = False) -> bool:
    """Format a single file using black and isort."""
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return False
    
    if not file_path.endswith('.py'):
        print(f"❌ Not a Python file: {file_path}")
        return False
    
    print(f"📝 Formatting: {file_path}")
    
    if dry_run:
        print("🔍 DRY RUN - checking what would be formatted...")
        
        # Check what black would change
        exit_code, stdout, stderr = run_command([
            "black", "--check", "--diff", file_path
        ])
        
        if exit_code == 0:
            print("✅ File is already properly formatted (black)")
        else:
            print("📝 Black would make changes:")
            print(stdout)
        
        # Check what isort would change
        exit_code, stdout, stderr = run_command([
            "isort", "--check-only", "--diff", file_path
        ])
        
        if exit_code == 0:
            print("✅ File is already properly formatted (isort)")
        else:
            print("📝 isort would make changes:")
            print(stdout)
        
        return True
    
    # Format with isort first
    print("🔄 Running isort...")
    exit_code, stdout, stderr = run_command(["isort", file_path])
    if exit_code != 0:
        print(f"❌ isort failed: {stderr}")
        return False
    
    # Format with black
    print("🔄 Running black...")
    exit_code, stdout, stderr = run_command(["black", file_path])
    if exit_code != 0:
        print(f"❌ black failed: {stderr}")
        return False
    
    print("✅ Formatting completed successfully")
    return True


def run_flake8(file_path: str) -> bool:
    """Run flake8 on the file to check for issues."""
    print("🔍 Running flake8...")
    exit_code, stdout, stderr = run_command(["flake8", file_path])
    
    if exit_code == 0:
        print("✅ flake8 passed - no issues found")
        return True
    else:
        print("⚠️  flake8 found issues:")
        print(stdout)
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Format a Python file with backup and testing"
    )
    parser.add_argument(
        "file_path",
        help="Path to the Python file to format"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a backup before formatting"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run tests after formatting"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making changes"
    )
    parser.add_argument(
        "--no-restore",
        action="store_true",
        help="Don't restore from backup if tests fail"
    )
    
    args = parser.parse_args()
    
    file_path = args.file_path
    backup_path = None
    
    # Validate file exists
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        sys.exit(1)
    
    print(f"🎯 Formatting file: {file_path}")
    print(f"📊 File size: {os.path.getsize(file_path)} bytes")
    
    # Create backup if requested
    if args.backup and not args.dry_run:
        backup_path = create_backup(file_path)
        if not backup_path:
            print("❌ Cannot proceed without backup")
            sys.exit(1)
    
    # Check syntax before formatting
    print("🔍 Checking syntax before formatting...")
    if not check_syntax(file_path):
        print("❌ Syntax check failed - cannot proceed")
        sys.exit(1)
    
    # Format the file
    if not format_file(file_path, args.dry_run):
        print("❌ Formatting failed")
        sys.exit(1)
    
    if args.dry_run:
        print("✅ Dry run completed")
        sys.exit(0)
    
    # Check syntax after formatting
    print("🔍 Checking syntax after formatting...")
    if not check_syntax(file_path):
        print("❌ Syntax check failed after formatting")
        if backup_path and not args.no_restore:
            restore_backup(file_path, backup_path)
        sys.exit(1)
    
    # Run flake8
    flake8_passed = run_flake8(file_path)
    
    # Run tests if requested
    tests_passed = True
    if args.test:
        print("🧪 Running import test...")
        tests_passed = test_import(file_path)
    
    # Summary
    print("\n" + "="*50)
    print("📋 FORMATTING SUMMARY")
    print("="*50)
    print(f"File: {file_path}")
    print(f"Syntax check: ✅ Passed")
    print(f"Formatting: ✅ Completed")
    print(f"flake8: {'✅ Passed' if flake8_passed else '⚠️  Issues found'}")
    print(f"Import test: {'✅ Passed' if tests_passed else '❌ Failed'}")
    
    if backup_path:
        print(f"Backup: {backup_path}")
    
    if not tests_passed and backup_path and not args.no_restore:
        print("\n🔄 Restoring from backup due to test failure...")
        if restore_backup(file_path, backup_path):
            print("✅ Restored successfully")
        else:
            print("❌ Failed to restore - manual intervention required")
            sys.exit(1)
    
    if tests_passed and flake8_passed:
        print("\n🎉 SUCCESS: File formatted successfully!")
        sys.exit(0)
    else:
        print("\n⚠️  WARNING: Formatting completed but some checks failed")
        sys.exit(1)


if __name__ == "__main__":
    main() 