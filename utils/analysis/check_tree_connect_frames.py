#!/usr/bin/env python3
"""
Check for specific Tree Connect frames in parquet files.
"""

import pandas as pd
import pyarrow.parquet as pq
import sys
import os

def check_frames_in_parquet(parquet_path: str, frame_numbers: list) -> None:
    """Check if specific frame numbers exist in parquet file."""
    print(f"Checking frames {frame_numbers} in: {parquet_path}")
    
    try:
        df = pq.read_table(parquet_path).to_pandas()
        print(f"Loaded {len(df)} total frames from parquet")
        
        # Check if frame.number column exists
        if 'frame.number' not in df.columns:
            print("ERROR: frame.number column not found in parquet file")
            return
        
        # Convert frame numbers to integers for comparison
        df['frame.number'] = df['frame.number'].astype(int)
        
        # Check each frame number
        for frame_num in frame_numbers:
            matching_rows = df[df['frame.number'] == frame_num]
            
            if len(matching_rows) > 0:
                print(f"\nFrame {frame_num} FOUND in parquet:")
                for idx, row in matching_rows.iterrows():
                    sesid = row.get('smb2.sesid', 'N/A')
                    cmd = row.get('smb2.cmd', 'N/A')
                    tid = row.get('smb2.tid', 'N/A')
                    tree = row.get('smb2.tree', 'N/A')
                    response = row.get('smb2.flags.response', 'N/A')
                    
                    print(f"  Session: {sesid}, Cmd: {cmd}, TID: {tid}, Tree: {tree}, Response: {response}")
            else:
                print(f"\nFrame {frame_num} NOT FOUND in parquet")
        
        # Also check for any Tree Connect frames (cmd=3)
        print(f"\nAll Tree Connect frames (cmd=3) in parquet:")
        tree_connects = df[df['smb2.cmd'] == '3']
        if len(tree_connects) > 0:
            for idx, row in tree_connects.iterrows():
                frame_num = row.get('frame.number', 'N/A')
                sesid = row.get('smb2.sesid', 'N/A')
                cmd = row.get('smb2.cmd', 'N/A')
                tid = row.get('smb2.tid', 'N/A')
                tree = row.get('smb2.tree', 'N/A')
                response = row.get('smb2.flags.response', 'N/A')
                
                print(f"  Frame {frame_num}: Session: {sesid}, Cmd: {cmd}, TID: {tid}, Tree: {tree}, Response: {response}")
        else:
            print("  No Tree Connect frames found in parquet")
        
    except Exception as e:
        print(f"Error loading parquet file: {e}")

def main():
    # Tree Connect frames from tshark output
    tree_connect_frames = [8434, 8453, 27202, 27203]
    
    # Base path from environment or default
    cases_dir = os.environ.get("TRACES_FOLDER", os.path.expanduser("~/cases"))
    case_id = os.environ.get("CASE_ID", "2010101010")
    trace_name = os.environ.get("TRACE_NAME", "trace")

    # Check in full parquet file
    full_parquet = os.path.join(cases_dir, case_id, ".tracer", trace_name, "sessions", "tshark_output_full.parquet")
    if os.path.exists(full_parquet):
        print("="*80)
        print("CHECKING FULL PARQUET FILE")
        print("="*80)
        check_frames_in_parquet(full_parquet, tree_connect_frames)
    else:
        print(f"Full parquet file not found: {full_parquet}")

    # Check in session-specific parquet file (our target session)
    session_parquet = os.path.join(cases_dir, case_id, ".tracer", trace_name, "sessions", "smb2_session_0x9dbc000000000006.parquet")
    if os.path.exists(session_parquet):
        print("\n" + "="*80)
        print("CHECKING SESSION-SPECIFIC PARQUET FILE (0x9dbc000000000006)")
        print("="*80)
        check_frames_in_parquet(session_parquet, tree_connect_frames)
    else:
        print(f"Session parquet file not found: {session_parquet}")

    # Check in the OTHER session-specific parquet file (the one with Tree Connect frames)
    other_session_parquet = os.path.join(cases_dir, case_id, ".tracer", trace_name, "sessions", "smb2_session_0x00012c01c400000d.parquet")
    if os.path.exists(other_session_parquet):
        print("\n" + "="*80)
        print("CHECKING OTHER SESSION-SPECIFIC PARQUET FILE (0x00012c01c400000d)")
        print("="*80)
        check_frames_in_parquet(other_session_parquet, tree_connect_frames)
    else:
        print(f"Other session parquet file not found: {other_session_parquet}")

if __name__ == "__main__":
    main()
