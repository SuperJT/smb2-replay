#!/usr/bin/env python3
"""
Compare PCAP file with parquet session file to analyze data processing and tree mapping.
"""

import pandas as pd
import pyarrow.parquet as pq
import subprocess
import sys
import os
import json
from typing import Dict, List, Optional, Tuple

def run_tshark_on_pcap(pcap_path: str, session_id: Optional[str] = None) -> pd.DataFrame:
    """Extract SMB2 data from PCAP for a specific session or all sessions."""
    print(f"Extracting SMB2 data from PCAP: {pcap_path}")
    if session_id:
        print(f"Filtering for session ID: {session_id}")
    else:
        print("Extracting all SMB2 data")
    
    # Key SMB2 fields we want to compare
    fields = [
        "frame.number",
        "smb2.sesid",
        "smb2.cmd",
        "smb2.flags.response",
        "smb2.tid",
        "smb2.filename",
        "smb2.tree",
        "smb2.nt_status"
    ]
    
    # Build tshark command
    if session_id:
        # Filter for specific session
        tshark_cmd = [
            "tshark",
            "-r", pcap_path,
            "-Y", "smb2",
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=y",
            "-E", "occurrence=a"
        ]
    else:
        # Get all SMB2 traffic
        tshark_cmd = [
            "tshark",
            "-r", pcap_path,
            "-Y", "smb2",
            "-T", "fields",
            "-E", "separator=|",
            "-E", "header=y",
            "-E", "occurrence=a"
        ]
    
    # Add field extractors
    for field in fields:
        tshark_cmd.extend(["-e", field])
    
    print(f"Running: {' '.join(tshark_cmd)}")
    
    try:
        result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
        
        if not result.stdout.strip():
            print("No SMB2 data found in PCAP")
            return pd.DataFrame()
        
        # Parse tshark output
        lines = result.stdout.strip().split('\n')
        header = lines[0].split('|')
        
        data = []
        for line in lines[1:]:
            if line.strip():
                values = line.split('|')
                # Pad with empty strings if needed
                while len(values) < len(header):
                    values.append('')
                data.append(dict(zip(header, values)))
        
        df = pd.DataFrame(data)
        
        # Filter by session ID if provided (post-process filtering)
        if session_id and not df.empty and 'smb2.sesid' in df.columns:
            original_count = len(df)
            df = df[df['smb2.sesid'] == session_id]
            print(f"Filtered from {original_count} to {len(df)} frames for session {session_id}")
        
        print(f"Extracted {len(df)} frames from PCAP")
        return df
        
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        print(f"stderr: {e.stderr}")
        return pd.DataFrame()

def load_parquet_session(parquet_path: str) -> pd.DataFrame:
    """Load session data from parquet file."""
    print(f"Loading session data from: {parquet_path}")
    
    try:
        df = pq.read_table(parquet_path).to_pandas()
        print(f"Loaded {len(df)} frames from parquet")
        return df
    except Exception as e:
        print(f"Error loading parquet file: {e}")
        return pd.DataFrame()

def compare_tree_connect_frames(pcap_df: pd.DataFrame, parquet_df: pd.DataFrame) -> None:
    """Compare Tree Connect frames between PCAP and parquet."""
    print("\n" + "="*80)
    print("TREE CONNECT FRAME COMPARISON")
    print("="*80)
    
    # Find Tree Connect frames in PCAP (cmd=3)
    pcap_tree_connects = pcap_df[pcap_df['smb2.cmd'] == '3']
    parquet_tree_connects = parquet_df[parquet_df['smb2.cmd'] == '3']
    
    print(f"Tree Connect frames in PCAP: {len(pcap_tree_connects)}")
    print(f"Tree Connect frames in parquet: {len(parquet_tree_connects)}")
    
    if len(pcap_tree_connects) > 0:
        print(f"\nTree Connect frames found in PCAP:")
        for idx, row in pcap_tree_connects.iterrows():
            frame_num = row.get('frame.number', 'N/A')
            cmd = row.get('smb2.cmd', 'N/A')
            is_response = row.get('smb2.flags.response', 'N/A')
            tid = row.get('smb2.tid', 'N/A')
            tree_path = row.get('smb2.tree', 'N/A')
            
            print(f"  Frame {frame_num}: cmd={cmd}, response={is_response}, tid={tid}, tree={tree_path}")
    
    if len(parquet_tree_connects) > 0:
        print(f"\nTree Connect frames found in parquet:")
        for idx, row in parquet_tree_connects.iterrows():
            frame_num = row.get('frame.number', 'N/A')
            cmd = row.get('smb2.cmd', 'N/A')
            is_response = row.get('smb2.flags.response', 'N/A')
            tid = row.get('smb2.tid', 'N/A')
            tree_path = row.get('smb2.tree', 'N/A')
            
            print(f"  Frame {frame_num}: cmd={cmd}, response={is_response}, tid={tid}, tree={tree_path}")

def compare_command_distribution(pcap_df: pd.DataFrame, parquet_df: pd.DataFrame) -> None:
    """Compare command distribution between PCAP and parquet."""
    print("\n" + "="*80)
    print("COMMAND DISTRIBUTION COMPARISON")
    print("="*80)
    
    # Get command counts
    pcap_cmds = pcap_df['smb2.cmd'].value_counts().sort_index()
    parquet_cmds = parquet_df['smb2.cmd'].value_counts().sort_index()
    
    print(f"{'Command':<10} {'PCAP Count':<12} {'Parquet Count':<15} {'Difference'}")
    print("-" * 60)
    
    all_cmds = set(pcap_cmds.index) | set(parquet_cmds.index)
    for cmd in sorted(all_cmds):
        pcap_count = pcap_cmds.get(cmd, 0)
        parquet_count = parquet_cmds.get(cmd, 0)
        diff = parquet_count - pcap_count
        
        print(f"{cmd:<10} {pcap_count:<12} {parquet_count:<15} {diff:+d}")

def compare_frame_ranges(pcap_df: pd.DataFrame, parquet_df: pd.DataFrame) -> None:
    """Compare frame number ranges."""
    print("\n" + "="*80)
    print("FRAME RANGE COMPARISON")
    print("="*80)
    
    if 'frame.number' in pcap_df.columns and len(pcap_df) > 0:
        pcap_frames = pcap_df['frame.number'].astype(int)
        pcap_min, pcap_max = pcap_frames.min(), pcap_frames.max()
        print(f"PCAP frame range: {pcap_min} - {pcap_max} ({len(pcap_df)} frames)")
    else:
        print("PCAP frame range: No frame data")
    
    if 'frame.number' in parquet_df.columns and len(parquet_df) > 0:
        parquet_frames = parquet_df['frame.number'].astype(int)
        parquet_min, parquet_max = parquet_frames.min(), parquet_frames.max()
        print(f"Parquet frame range: {parquet_min} - {parquet_max} ({len(parquet_df)} frames)")
    else:
        print("Parquet frame range: No frame data")

def compare_tree_ids(pcap_df: pd.DataFrame, parquet_df: pd.DataFrame) -> None:
    """Compare tree ID usage between PCAP and parquet."""
    print("\n" + "="*80)
    print("TREE ID USAGE COMPARISON")
    print("="*80)
    
    # Get unique tree IDs
    pcap_tids = set(pcap_df['smb2.tid'].dropna().unique())
    parquet_tids = set(parquet_df['smb2.tid'].dropna().unique())
    
    print(f"Tree IDs in PCAP: {sorted(pcap_tids)}")
    print(f"Tree IDs in parquet: {sorted(parquet_tids)}")
    
    common_tids = pcap_tids & parquet_tids
    pcap_only = pcap_tids - parquet_tids
    parquet_only = parquet_tids - pcap_tids
    
    print(f"Common tree IDs: {sorted(common_tids)}")
    if pcap_only:
        print(f"Tree IDs only in PCAP: {sorted(pcap_only)}")
    if parquet_only:
        print(f"Tree IDs only in parquet: {sorted(parquet_only)}")

def main():
    if len(sys.argv) not in [2, 3]:
        print("Usage: python compare_pcap_parquet.py <pcap_file> [session_id]")
        print("       python compare_pcap_parquet.py <pcap_file> <full_parquet_file>")
        print("Examples:")
        print("  python compare_pcap_parquet.py /path/to/capture.pcap 0x123456")
        print("  python compare_pcap_parquet.py /path/to/capture.pcap /path/to/tshark_output_full.parquet")
        sys.exit(1)
    
    pcap_path = sys.argv[1]
    
    # Validate PCAP file exists
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)
    
    if len(sys.argv) == 3:
        second_arg = sys.argv[2]
        
        # Check if second argument is a parquet file or session ID
        if second_arg.endswith('.parquet'):
            # Full parquet file provided
            parquet_path = second_arg
            session_id = None
            
            if not os.path.exists(parquet_path):
                print(f"Error: Parquet file not found: {parquet_path}")
                sys.exit(1)
        else:
            # Session ID provided - need to find the full parquet file
            session_id = second_arg
            
            # Try to find the full parquet file in the same directory structure
            session_parquet_path = f"smb2_session_{session_id}.parquet"
            
            # Look for the full parquet file in common locations
            cases_dir = os.environ.get("TRACES_FOLDER", os.path.expanduser("~/cases"))
            possible_paths = [
                f"{cases_dir}/*/sessions/tshark_output_full.parquet",
                f"{cases_dir}/*/.tracer/*/sessions/tshark_output_full.parquet"
            ]
            
            parquet_path = None
            for pattern in possible_paths:
                import glob
                matches = glob.glob(pattern)
                if matches:
                    parquet_path = matches[0]  # Use first match
                    break
            
            if not parquet_path:
                print(f"Error: Could not find full parquet file for session {session_id}")
                print("Please provide the full parquet file path directly:")
                print("  python compare_pcap_parquet.py <pcap_file> <full_parquet_file>")
                sys.exit(1)
    else:
        print("Error: Please provide either a session ID or full parquet file path")
        sys.exit(1)
    
    print(f"Comparing PCAP and full parquet file")
    if session_id:
        print(f"Filtering for session: {session_id}")
    print("="*80)
    
    # Load data
    pcap_df = run_tshark_on_pcap(pcap_path, session_id)
    parquet_df = load_parquet_session(parquet_path)
    
    # Filter parquet data by session ID if provided
    if session_id and not parquet_df.empty:
        if 'smb2.sesid' in parquet_df.columns:
            print(f"Filtering parquet data for session: {session_id}")
            parquet_df = parquet_df[parquet_df['smb2.sesid'] == session_id]
            print(f"Filtered to {len(parquet_df)} frames for session {session_id}")
    
    if pcap_df.empty:
        print("No data found in PCAP - cannot compare")
        sys.exit(1)
    
    if parquet_df.empty:
        print("No data found in parquet - cannot compare")
        sys.exit(1)
    
    # Run comparisons
    compare_frame_ranges(pcap_df, parquet_df)
    compare_command_distribution(pcap_df, parquet_df)
    compare_tree_ids(pcap_df, parquet_df)
    compare_tree_connect_frames(pcap_df, parquet_df)
    
    print("\n" + "="*80)
    print("COMPARISON COMPLETE")
    print("="*80)

if __name__ == "__main__":
    main()
