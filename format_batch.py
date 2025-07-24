#!/usr/bin/env python3
"""
SMBReplay Batch Formatting Script

This script formats multiple Python files according to the formatting strategy
defined in the inventory. It processes files in the correct order to avoid
dependency issues.

Usage:
    python format_batch.py [--phase <phase>] [--dry-run] [--backup] [--test]
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any


# File categories based on the inventory
FILE_CATEGORIES = {
    "core_modules": [
        "smbreplay_package/smbreplay/__init__.py",
        "smbreplay_package/smbreplay/config.py",
        "smbreplay_package/smbreplay/constants.py",
        "smbreplay_package/smbreplay/utils.py",
    ],
    "handlers": [
        # Small handlers first
        "smbreplay_package/smbreplay/handlers/negotiate.py",
        "smbreplay_package/smbreplay/handlers/session_setup.py",
        "smbreplay_package/smbreplay/handlers/logoff.py",
        "smbreplay_package/smbreplay/handlers/tree_disconnect.py",
        "smbreplay_package/smbreplay/handlers/tree_connect.py",
        "smbreplay_package/smbreplay/handlers/response.py",
        "smbreplay_package/smbreplay/handlers/close.py",
        "smbreplay_package/smbreplay/handlers/read.py",
        "smbreplay_package/smbreplay/handlers/write.py",
        "smbreplay_package/smbreplay/handlers/flush.py",
        "smbreplay_package/smbreplay/handlers/set_info.py",
        "smbreplay_package/smbreplay/handlers/cancel.py",
        "smbreplay_package/smbreplay/handlers/echo.py",
        "smbreplay_package/smbreplay/handlers/__init__.py",
        "smbreplay_package/smbreplay/handlers/oplock_break.py",
        "smbreplay_package/smbreplay/handlers/lease_break.py",
        "smbreplay_package/smbreplay/handlers/lock.py",
        "smbreplay_package/smbreplay/handlers/change_notify.py",
        "smbreplay_package/smbreplay/handlers/create.py",
        "smbreplay_package/smbreplay/handlers/ioctl.py",
        "smbreplay_package/smbreplay/handlers/query_info.py",
        "smbreplay_package/smbreplay/handlers/query_directory.py",
    ],
    "large_core": [
        "smbreplay_package/smbreplay/tshark_processor.py",
        "smbreplay_package/smbreplay/ingestion.py",
        "smbreplay_package/smbreplay/session_manager.py",
        "smbreplay_package/smbreplay/replay.py",
        "smbreplay_package/smbreplay/main.py",
    ],
    "test_utils": [
        "smbreplay_package/smbreplay/__main__.py",
        "smbreplay_package/smbreplay/test_environment.py",
        "smbreplay_package/smbreplay/test_conversion.py",
        "smbreplay_package/smbreplay/performance_monitor.py",
    ],
    "additional": [
        "smbreplay_package/setup.py",
        "debug_create_action.py",
    ]
}

# Phase definitions
PHASES = {
    "1": "core_modules",
    "2": "handlers", 
    "3": "large_core",
    "4": "test_utils",
    "5": "additional"
}


def run_format_file(file_path: str, args: argparse.Namespace) -> bool:
    """Run the format_file.py script on a single file."""
    cmd = [sys.executable, "format_file.py", file_path]
    
    if args.backup:
        cmd.append("--backup")
    if args.test:
        cmd.append("--test")
    if args.dry_run:
        cmd.append("--dry-run")
    
    print(f"\n🔄 Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except Exception as e:
        print(f"❌ Error running format_file.py: {e}")
        return False


def check_file_exists(file_path: str) -> bool:
    """Check if a file exists."""
    return os.path.exists(file_path)


def get_phase_files(phase: str) -> List[str]:
    """Get the list of files for a specific phase."""
    if phase in FILE_CATEGORIES:
        return FILE_CATEGORIES[phase]
    elif phase in PHASES:
        return FILE_CATEGORIES[PHASES[phase]]
    else:
        return []


def format_phase(phase: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Format all files in a specific phase."""
    files = get_phase_files(phase)
    
    if not files:
        print(f"❌ No files found for phase: {phase}")
        return {"success": False, "processed": 0, "failed": 0}
    
    print(f"\n{'='*60}")
    print(f"📋 PHASE {phase}: {len(files)} files")
    print(f"{'='*60}")
    
    results: Dict[str, Any] = {
        "success": True,
        "processed": 0,
        "failed": 0,
        "files": []
    }
    
    for i, file_path in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] Processing: {file_path}")
        
        if not check_file_exists(file_path):
            print(f"⚠️  File not found: {file_path}")
            results["files"].append({
                "file": file_path,
                "status": "not_found",
                "error": "File does not exist"
            })
            continue
        
        success = run_format_file(file_path, args)
        
        if success:
            results["processed"] += 1
            results["files"].append({
                "file": file_path,
                "status": "success"
            })
        else:
            results["failed"] += 1
            results["success"] = False
            results["files"].append({
                "file": file_path,
                "status": "failed"
            })
            
            if not args.dry_run:
                print(f"❌ Failed to format: {file_path}")
                response = input("Continue with next file? (y/n): ")
                if response.lower() != 'y':
                    print("🛑 Stopping due to user request")
                    break
    
    return results


def print_summary(results: Dict[str, Any], phase: str):
    """Print a summary of the formatting results."""
    print(f"\n{'='*60}")
    print(f"📊 PHASE {phase} SUMMARY")
    print(f"{'='*60}")
    print(f"Total files: {results['processed'] + results['failed']}")
    print(f"Successfully processed: {results['processed']}")
    print(f"Failed: {results['failed']}")
    print(f"Overall success: {'✅ Yes' if results['success'] else '❌ No'}")
    
    if results['failed'] > 0:
        print("\nFailed files:")
        for file_result in results['files']:
            if file_result['status'] == 'failed':
                print(f"  - {file_result['file']}")
            elif file_result['status'] == 'not_found':
                print(f"  - {file_result['file']} (not found)")


def main():
    parser = argparse.ArgumentParser(
        description="Batch format Python files according to SMBReplay strategy"
    )
    parser.add_argument(
        "--phase",
        choices=["1", "2", "3", "4", "5", "all"],
        default="all",
        help="Which phase to run (1=core, 2=handlers, 3=large_core, 4=test_utils, 5=additional, all=all phases)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without making changes"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create backups before formatting"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run tests after formatting each file"
    )
    parser.add_argument(
        "--list-phases",
        action="store_true",
        help="List all phases and their files"
    )
    
    args = parser.parse_args()
    
    if args.list_phases:
        print("📋 FORMATTING PHASES")
        print("="*50)
        for phase_num, phase_name in PHASES.items():
            files = FILE_CATEGORIES[phase_name]
            print(f"\nPhase {phase_num}: {phase_name} ({len(files)} files)")
            for file_path in files:
                exists = "✅" if check_file_exists(file_path) else "❌"
                print(f"  {exists} {file_path}")
        return
    
    print("🎯 SMBReplay Batch Formatting")
    print("="*50)
    print(f"Phase: {args.phase}")
    print(f"Dry run: {'Yes' if args.dry_run else 'No'}")
    print(f"Backup: {'Yes' if args.backup else 'No'}")
    print(f"Test: {'Yes' if args.test else 'No'}")
    
    if args.phase == "all":
        # Run all phases in order
        overall_success = True
        total_processed = 0
        total_failed = 0
        
        for phase_num in ["1", "2", "3", "4", "5"]:
            phase_name = PHASES[phase_num]
            results = format_phase(phase_name, args)
            
            print_summary(results, phase_name)
            
            total_processed += results["processed"]
            total_failed += results["failed"]
            
            if not results["success"]:
                overall_success = False
                
                if not args.dry_run:
                    response = input(f"\nPhase {phase_num} had failures. Continue to next phase? (y/n): ")
                    if response.lower() != 'y':
                        print("🛑 Stopping due to user request")
                        break
        
        print(f"\n{'='*60}")
        print("📊 OVERALL SUMMARY")
        print(f"{'='*60}")
        print(f"Total files processed: {total_processed}")
        print(f"Total files failed: {total_failed}")
        print(f"Overall success: {'✅ Yes' if overall_success else '❌ No'}")
        
    else:
        # Run specific phase
        phase_name = PHASES[args.phase]
        results = format_phase(phase_name, args)
        print_summary(results, args.phase)
    
    if args.dry_run:
        print("\n🔍 This was a dry run - no files were actually modified")
    else:
        print("\n🎉 Batch formatting completed!")


if __name__ == "__main__":
    main() 