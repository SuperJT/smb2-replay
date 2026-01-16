#!/usr/bin/env python3
"""
Check EOF and allocation_size fields in actual ingested parquet data.
This script queries the database/parquet files via the API service.
"""

import sys
import os
from pathlib import Path

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "smbreplay_package"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "api"))

from api.services.smbreplay_service import SMBReplayService

def check_eof_fields():
    """Check if EOF and allocation_size fields contain data in ingested sessions."""
    
    print("=" * 80)
    print("Checking EOF and allocation_size fields in ingested parquet data")
    print("=" * 80)
    
    # Initialize service
    service = SMBReplayService()
    
    # Get available sessions
    print("\nListing available sessions...")
    try:
        sessions_response = service.list_sessions(capture_path=None)
        sessions = sessions_response.get('sessions', [])
        
        if not sessions:
            print("No sessions found. Need to ingest a trace first.")
            return
        
        print(f"Found {len(sessions)} session(s)")
        
        # Check first session
        session = sessions[0]
        session_id = session.get('session_id', session.get('file_name'))
        print(f"\nChecking session: {session_id}")
        
        # Get operations
        operations_data = service.get_session_operations(
            session_id=session_id,
            fields=None  # Get all fields
        )
        
        operations = operations_data.get('operations', [])
        total_ops = len(operations)
        
        print(f"Total operations: {total_ops}")
        
        if total_ops == 0:
            print("No operations found in session")
            return
        
        # Check for EOF and allocation_size fields
        first_op = operations[0]
        has_eof = 'smb2.eof' in first_op
        has_alloc = 'smb2.allocation_size' in first_op
        has_response_flag = 'smb2.flags.response' in first_op
        
        print(f"\nField presence in operations:")
        print(f"  smb2.eof: {has_eof}")
        print(f"  smb2.allocation_size: {has_alloc}")
        print(f"  smb2.flags.response: {has_response_flag}")
        
        if not has_eof:
            print("\nERROR: smb2.eof field not found in operations!")
            return
        
        if not has_alloc:
            print("\nERROR: smb2.allocation_size field not found in operations!")
            return
        
        # Count non-empty values
        eof_populated = sum(
            1 for op in operations 
            if op.get('smb2.eof') and str(op.get('smb2.eof')).strip()
        )
        
        alloc_populated = sum(
            1 for op in operations 
            if op.get('smb2.allocation_size') and str(op.get('smb2.allocation_size')).strip()
        )
        
        print(f"\nField population statistics:")
        print(f"  smb2.eof non-empty: {eof_populated}/{total_ops} ({100*eof_populated/total_ops:.1f}%)")
        print(f"  smb2.allocation_size non-empty: {alloc_populated}/{total_ops} ({100*alloc_populated/total_ops:.1f}%)")
        
        # Find CREATE responses with EOF data
        create_responses = [
            op for op in operations 
            if op.get('Command') == 'CREATE'
            and op.get('smb2.flags.response') == 'True'
        ]
        
        print(f"\nCREATE responses: {len(create_responses)}")
        
        if create_responses:
            create_with_eof = sum(
                1 for op in create_responses
                if op.get('smb2.eof') and str(op.get('smb2.eof')).strip()
            )
            print(f"CREATE responses with EOF data: {create_with_eof}/{len(create_responses)}")
            
            # Show samples
            if create_with_eof > 0:
                print("\nSample CREATE responses with EOF data:")
                count = 0
                for op in create_responses:
                    eof = op.get('smb2.eof')
                    if eof and str(eof).strip():
                        print(f"  Frame {op.get('Frame')}: EOF={eof}, Alloc={op.get('smb2.allocation_size')}, File={op.get('smb2.filename', 'N/A')[:60]}")
                        count += 1
                        if count >= 5:
                            break
            else:
                print("\n⚠ WARNING: No CREATE responses have EOF data!")
                print("This indicates the fields are being extracted but are empty.")
                
                # Show a sample CREATE response
                print("\nSample CREATE response (checking all fields):")
                sample = create_responses[0]
                print(f"  Frame: {sample.get('Frame')}")
                print(f"  Command: {sample.get('Command')}")
                print(f"  smb2.cmd: {sample.get('smb2.cmd')}")
                print(f"  smb2.flags.response: {sample.get('smb2.flags.response')}")
                print(f"  smb2.eof: '{sample.get('smb2.eof')}'")
                print(f"  smb2.allocation_size: '{sample.get('smb2.allocation_size')}'")
                print(f"  smb2.filename: {sample.get('smb2.filename')}")
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        if eof_populated > 0 or alloc_populated > 0:
            print("✓ EOF/allocation_size fields ARE being populated!")
            print(f"  Data appears in {max(eof_populated, alloc_populated)} operations")
        else:
            print("✗ EOF/allocation_size fields are EMPTY")
            print("  Problem confirmed: Fields exist but contain no data")
            print("\nPossible causes:")
            print("  1. Tshark not extracting the fields from PCAP")
            print("  2. Fields being filtered out during ingestion")
            print("  3. Data type conversion issue in parquet write")
            print("  4. Request/response pairing issue")
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_eof_fields()
