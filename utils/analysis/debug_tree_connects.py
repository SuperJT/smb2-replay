#!/usr/bin/env python3
"""
Debug script to examine Tree Connect frames in the session data.
"""

import os
import sys

import pandas as pd
import pyarrow.parquet as pq


def debug_tree_connects(session_file):
    """Debug Tree Connect frames in the session data."""
    if not os.path.exists(session_file):
        print(f"Session file not found: {session_file}")
        return

    print(f"Loading session file: {session_file}")

    try:
        # Load the session data
        df = pq.read_table(session_file).to_pandas()
        print(f"Loaded {len(df)} total frames")

        # Show unique command values to understand what's actually in the data
        if "smb2.cmd" in df.columns:
            unique_cmds = df["smb2.cmd"].unique()
            print(f"Unique SMB2 commands found: {sorted(unique_cmds)}")

            # Show command counts
            cmd_counts = df["smb2.cmd"].value_counts().sort_index()
            print("Command counts:")
            for cmd, count in cmd_counts.items():
                print(f"  Command {cmd}: {count} frames")
        else:
            print("No 'smb2.cmd' column found")

        # Check for different possible command column names
        cmd_columns = [col for col in df.columns if "cmd" in col.lower()]
        print(f"Columns containing 'cmd': {cmd_columns}")

        # Look for tree-related columns
        tree_columns = [col for col in df.columns if "tree" in col.lower()]
        print(f"Columns containing 'tree': {tree_columns}")

        # Try different ways to find Tree Connect frames
        # Tree Connect command is 3
        tree_connects_str = df[df["smb2.cmd"] == "3"]
        tree_connects_int = df[df["smb2.cmd"] == 3]
        tree_connects_hex = df[df["smb2.cmd"] == "0x3"]

        print(f"Found {len(tree_connects_str)} Tree Connect frames (string '3')")
        print(f"Found {len(tree_connects_int)} Tree Connect frames (int 3)")
        print(f"Found {len(tree_connects_hex)} Tree Connect frames (hex '0x3')")

        # Use whichever method found frames
        if len(tree_connects_str) > 0:
            tree_connects = tree_connects_str
        elif len(tree_connects_int) > 0:
            tree_connects = tree_connects_int
        elif len(tree_connects_hex) > 0:
            tree_connects = tree_connects_hex
        else:
            print("No Tree Connect frames found with any method")

            # Show sample of all frames to understand structure
            print("\nSample of first 5 frames to understand structure:")
            for idx in range(min(5, len(df))):
                row = df.iloc[idx]
                print(f"\nFrame {idx} (row {row.get('frame.number', 'N/A')}):")
                print(f"  smb2.cmd: {row.get('smb2.cmd', 'N/A')}")
                print(f"  smb2.flags.response: {row.get('smb2.flags.response', 'N/A')}")
                print(f"  smb2.tid: {row.get('smb2.tid', 'N/A')}")

                # Show any tree-related fields
                for col in tree_columns:
                    value = row.get(col, "N/A")
                    if pd.notna(value) and str(value).strip() != "":
                        print(f"  {col}: {value}")
            return

        # Show all columns to understand the structure
        print(f"\nAvailable columns ({len(df.columns)}):")
        for i, col in enumerate(sorted(df.columns)):
            print(f"  {i + 1:3d}. {col}")

        # Focus on Tree Connect frames
        print("\nTree Connect frames:")
        print("=" * 100)

        for idx, row in tree_connects.iterrows():
            frame_num = row.get("frame.number", "N/A")
            cmd = row.get("smb2.cmd", "N/A")
            is_response = row.get("smb2.flags.response", "N/A")
            tid = row.get("smb2.tid", "N/A")
            tree_path = row.get("smb2.tree", "N/A")
            nt_status = row.get("smb2.nt_status", "N/A")

            print(f"Frame {frame_num}: cmd={cmd}, response={is_response}, tid={tid}")
            print(f"  Tree path: {tree_path}")
            print(f"  NT Status: {nt_status}")

            # Show all non-null SMB2 fields for this frame
            smb2_fields = {
                k: v
                for k, v in row.items()
                if k.startswith("smb2.") and pd.notna(v) and v != ""
            }
            if smb2_fields:
                print(f"  SMB2 fields ({len(smb2_fields)}):")
                for field, value in sorted(smb2_fields.items()):
                    print(f"    {field}: {value}")
            print()

    except Exception as e:
        print(f"Error loading session file: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python debug_tree_connects.py <session_file.parquet>")
        sys.exit(1)

    debug_tree_connects(sys.argv[1])
