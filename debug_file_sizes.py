#!/usr/bin/env python3
"""
Debug script to trace _extract_file_sizes logic with actual operations data.
Run inside container to diagnose why file sizes aren't being extracted.
"""

import sys
from typing import Any

# Add the smbreplay package to path
sys.path.insert(0, '/opt/venv/lib/python3.12/site-packages')

from smbreplay.main import SMB2ReplaySystem


def _safe_op_get(op: dict[str, Any], key: str, default: Any = "") -> Any:
    """Safely get operation field."""
    return op.get(key, default) if isinstance(op, dict) else default


def debug_extract_file_sizes(operations: list[dict[str, Any]]) -> dict[str, int]:
    """
    Debug version of _extract_file_sizes with verbose logging.
    """
    file_sizes = {}
    
    print(f"\n{'='*80}")
    print(f"STARTING FILE SIZE EXTRACTION")
    print(f"Total operations to analyze: {len(operations)}")
    print(f"{'='*80}\n")
    
    # Counters for statistics
    stats = {
        'total_ops': len(operations),
        'create_responses': 0,
        'create_with_eof': 0,
        'create_with_alloc': 0,
        'set_info_ops': 0,
        'set_info_size_ops': 0,
        'write_ops': 0,
        'files_with_sizes': 0,
    }
    
    # Sample operations for debugging
    sample_creates = []
    sample_set_infos = []
    sample_writes = []
    
    for idx, op in enumerate(operations):
        if not isinstance(op, dict):
            continue
            
        filename = _safe_op_get(op, "smb2.filename", "")
        if not filename or filename in [".", "..", "N/A", ""]:
            continue
            
        normalized_path = filename.lstrip("\\/")
        cmd = _safe_op_get(op, "smb2.cmd", "")
        is_response = _safe_op_get(op, "smb2.flags.response", "") == "True"
        
        # Check CREATE responses
        if cmd == "5" and is_response:
            stats['create_responses'] += 1
            
            # Sample first 3 CREATE responses
            if len(sample_creates) < 3:
                sample_creates.append({
                    'idx': idx,
                    'filename': filename,
                    'eof': _safe_op_get(op, "smb2.eof", None),
                    'allocation_size': _safe_op_get(op, "smb2.allocation_size", None),
                    'create_action': _safe_op_get(op, "smb2.create.action", None),
                    'keys': list(op.keys())[:20]  # First 20 keys
                })
            
            # Try smb2.eof
            eof = _safe_op_get(op, "smb2.eof", None)
            if eof and eof != "0":
                try:
                    size = int(eof)
                    if size > 0:
                        stats['create_with_eof'] += 1
                        file_sizes[normalized_path] = max(
                            file_sizes.get(normalized_path, 0), size
                        )
                        print(f"✓ CREATE EOF: {normalized_path} = {size} bytes (op {idx})")
                except (ValueError, TypeError) as e:
                    print(f"✗ CREATE EOF parse error: {filename} eof={eof} error={e}")
                    
            # Try smb2.allocation_size
            alloc_size = _safe_op_get(op, "smb2.allocation_size", None)
            if alloc_size and alloc_size != "0":
                try:
                    size = int(alloc_size)
                    if size > 0:
                        stats['create_with_alloc'] += 1
                        file_sizes[normalized_path] = max(
                            file_sizes.get(normalized_path, 0), size
                        )
                        print(f"✓ CREATE ALLOC: {normalized_path} = {size} bytes (op {idx})")
                except (ValueError, TypeError) as e:
                    print(f"✗ CREATE ALLOC parse error: {filename} alloc={alloc_size} error={e}")
        
        # Check SET_INFO operations
        elif cmd == "17":
            stats['set_info_ops'] += 1
            info_type = _safe_op_get(op, "smb2.setinfo.info_type", "")
            file_info_class = _safe_op_get(op, "smb2.setinfo.file_info_class", "")
            
            # Sample first 3 SET_INFO ops
            if len(sample_set_infos) < 3:
                sample_set_infos.append({
                    'idx': idx,
                    'filename': filename,
                    'info_type': info_type,
                    'file_info_class': file_info_class,
                    'eof': _safe_op_get(op, "smb2.eof", None),
                    'keys': list(op.keys())[:20]
                })
            
            if info_type == "1" and file_info_class in ["19", "20"]:
                stats['set_info_size_ops'] += 1
                eof = _safe_op_get(op, "smb2.eof", None)
                if eof and eof != "0":
                    try:
                        size = int(eof)
                        if size > 0:
                            file_sizes[normalized_path] = max(
                                file_sizes.get(normalized_path, 0), size
                            )
                            print(f"✓ SET_INFO: {normalized_path} = {size} bytes (class={file_info_class}, op {idx})")
                    except (ValueError, TypeError) as e:
                        print(f"✗ SET_INFO parse error: {filename} eof={eof} error={e}")
                        
        # Check WRITE operations
        elif cmd == "9":
            stats['write_ops'] += 1
            
            # Sample first 3 WRITE ops
            if len(sample_writes) < 3:
                sample_writes.append({
                    'idx': idx,
                    'filename': filename,
                    'offset': _safe_op_get(op, "smb2.file_offset", None),
                    'length': _safe_op_get(op, "smb2.write.length", None),
                    'keys': list(op.keys())[:20]
                })
            
            offset = _safe_op_get(op, "smb2.file_offset", None)
            length = _safe_op_get(op, "smb2.write.length", None)
            if offset and length:
                try:
                    write_end = int(offset) + int(length)
                    if write_end > 0:
                        file_sizes[normalized_path] = max(
                            file_sizes.get(normalized_path, 0), write_end
                        )
                        print(f"✓ WRITE: {normalized_path} = {write_end} bytes (offset={offset}+len={length}, op {idx})")
                except (ValueError, TypeError) as e:
                    print(f"✗ WRITE parse error: {filename} offset={offset} length={length} error={e}")
    
    stats['files_with_sizes'] = len(file_sizes)
    
    # Print summary
    print(f"\n{'='*80}")
    print(f"EXTRACTION SUMMARY")
    print(f"{'='*80}")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    print(f"\n  Files with sizes extracted: {len(file_sizes)}")
    if file_sizes:
        print(f"  Size range: {min(file_sizes.values())} - {max(file_sizes.values())} bytes")
    print(f"{'='*80}\n")
    
    # Print samples
    if sample_creates:
        print(f"\n{'='*80}")
        print("SAMPLE CREATE RESPONSES (first 3):")
        print(f"{'='*80}")
        for sample in sample_creates:
            print(f"\nOp {sample['idx']}: {sample['filename']}")
            print(f"  eof: {sample['eof']}")
            print(f"  allocation_size: {sample['allocation_size']}")
            print(f"  create_action: {sample['create_action']}")
            print(f"  Available keys (first 20): {sample['keys']}")
    
    if sample_set_infos:
        print(f"\n{'='*80}")
        print("SAMPLE SET_INFO OPERATIONS (first 3):")
        print(f"{'='*80}")
        for sample in sample_set_infos:
            print(f"\nOp {sample['idx']}: {sample['filename']}")
            print(f"  info_type: {sample['info_type']}")
            print(f"  file_info_class: {sample['file_info_class']}")
            print(f"  eof: {sample['eof']}")
            print(f"  Available keys (first 20): {sample['keys']}")
    
    if sample_writes:
        print(f"\n{'='*80}")
        print("SAMPLE WRITE OPERATIONS (first 3):")
        print(f"{'='*80}")
        for sample in sample_writes:
            print(f"\nOp {sample['idx']}: {sample['filename']}")
            print(f"  offset: {sample['offset']}")
            print(f"  length: {sample['length']}")
            print(f"  Available keys (first 20): {sample['keys']}")
    
    return file_sizes


async def main():
    """Main debug function."""
def main():
    """Main debug function."""
    # Get session ID from command line
    if len(sys.argv) < 2:
        print("Usage: python debug_file_sizes.py <session_id>")
        print("Example: python debug_file_sizes.py 0xd2020000031cefe3")
        sys.exit(1)
    
    session_id = sys.argv[1]
    print(f"\nDebug File Sizes for Session: {session_id}")
    print(f"{'='*80}\n")
    
    # Initialize the SMB2ReplaySystem (like the API does)
    print("Initializing SMB2ReplaySystem...")
    system = SMB2ReplaySystem()
    system.setup_system()
    print("✓ System initialized\n")
    
    try:
        # Load session using get_session_info (same as API)
        print(f"Loading session {session_id} via get_session_info()...")
        
        # Normalize session ID to file name format
        session_file = f"smb2_session_{session_id}.parquet"
        
        operations = system.get_session_info(
            session_file,
            capture_path=None,  # Will use configured path
            file_filter=None,
            fields=None,
        )
        
        if not operations:
            print(f"ERROR: Could not load operations for session {session_id}")
            print("  Trying without .parquet extension...")
            operations = system.get_session_info(
                session_id,
                capture_path=None,
                file_filter=None,
                fields=None,
            )
        
        if not operations:
            print(f"ERROR: Still could not load session {session_id}")
            sys.exit(1)
        
        print(f"✓ Loaded {len(operations)} operations\n")
        
        # Show first operation structure
        if operations:
            print(f"{'='*80}")
            print("FIRST OPERATION STRUCTURE:")
            print(f"{'='*80}")
            first_op = operations[0]
            print(f"Type: {type(first_op)}")
            if isinstance(first_op, dict):
                print(f"Keys: {list(first_op.keys())}")
                print(f"\nSample values:")
                for key in list(first_op.keys())[:10]:
                    value = first_op[key]
                    if isinstance(value, str) and len(value) > 100:
                        print(f"  {key}: {value[:100]}... (truncated)")
                    else:
                        print(f"  {key}: {value}")
            print(f"{'='*80}\n")
        
        # Run debug extraction
        file_sizes = debug_extract_file_sizes(operations)
        
        # Final results
        print(f"\n{'='*80}")
        print("FINAL RESULTS")
        print(f"{'='*80}")
        if file_sizes:
            print(f"✓ Successfully extracted {len(file_sizes)} file sizes:")
            for path, size in sorted(file_sizes.items())[:20]:  # Show first 20
                print(f"  {path}: {size:,} bytes")
            if len(file_sizes) > 20:
                print(f"  ... and {len(file_sizes) - 20} more files")
        else:
            print("✗ NO FILE SIZES EXTRACTED - This is the problem!")
            print("\nPossible causes:")
            print("  1. smb2.eof field not present in operations")
            print("  2. smb2.allocation_size field not present")
            print("  3. Field values are empty/null/zero")
            print("  4. Operations don't have expected structure")
            print("  5. Data not loaded correctly from database")
        print(f"{'='*80}\n")
        
    except Exception as e:
        print(f"\nERROR during debug: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
