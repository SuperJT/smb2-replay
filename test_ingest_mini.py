#!/usr/bin/env python3
"""
Test: Ingest a tiny sample and check EOF fields in the DataFrame.
"""

import sys
from pathlib import Path

# Monkey-patch logger
import logging
logging.basicConfig(level=logging.WARNING)  # Reduce noise

import smbreplay.config as config_module
config_module.get_logger = lambda: logging.getLogger("smbreplay")

sys.path.insert(0, str(Path(__file__).parent / "smbreplay_package"))

from smbreplay.tshark_processor import build_tshark_command, process_tshark_output
from smbreplay.constants import get_all_fields

# Test with small packet sample
pcap = "/Users/jtownsen/cases/2010101010/host.pcap26"
fields = get_all_fields()

print(f"Building tshark command with {len(fields)} fields...")
cmd, used_fields = build_tshark_command(pcap, fields, reassembly=False, packet_limit=500)

print("Processing tshark output...")
df = process_tshark_output(cmd, used_fields, max_records=500)

print(f"\nDataFrame shape: {df.shape}")
print(f"Columns with 'eof': {[c for c in df.columns if 'eof' in c.lower()]}")
print(f"Columns with 'alloc': {[c for c in df.columns if 'alloc' in c.lower()]}")

if 'smb2.eof' in df.columns:
    # Check for non-empty values
    eof_series = df['smb2.eof'].astype(str)
    non_empty = eof_series.str.strip().ne('').sum()
    print(f"\nsmb2.eof: {non_empty}/{len(df)} non-empty")
    
    # Show samples of non-empty
    if non_empty > 0:
        samples = df[eof_series.str.strip().ne('')][['smb2.cmd', 'smb2.flags.response', 'smb2.eof', 'smb2.allocation_size', 'smb2.filename']].head(10)
        print("\nSample rows with EOF data:")
        print(samples.to_string())
    
    # Show data types
    print(f"\nData type of smb2.eof: {df['smb2.eof'].dtype}")
    print(f"Unique values (first 20): {eof_series.unique()[:20]}")
else:
    print("\nERROR: smb2.eof column not found!")

if 'smb2.allocation_size' in df.columns:
    alloc_series = df['smb2.allocation_size'].astype(str)
    non_empty = alloc_series.str.strip().ne('').sum()
    print(f"\nsmb2.allocation_size: {non_empty}/{len(df)} non-empty")
    print(f"Data type: {df['smb2.allocation_size'].dtype}")
else:
    print("\nERROR: smb2.allocation_size column not found!")
