#!/usr/bin/env python3
"""
Simple test: Build tshark command and verify EOF fields are included.
"""

import sys
from pathlib import Path

# Add package to path
sys.path.insert(0, str(Path(__file__).parent / "smbreplay_package"))

# Monkey-patch logger to avoid state dir issues  
import logging
logging.basicConfig(level=logging.INFO)

import smbreplay.config as config_module
config_module.get_logger = lambda: logging.getLogger("smbreplay")

from smbreplay.tshark_processor import build_tshark_command
from smbreplay.constants import get_all_fields

# Test
pcap = "/Users/jtownsen/cases/2010101010/host.pcap26"
fields = get_all_fields()

print(f"Total fields: {len(fields)}")
print(f"smb2.eof in fields: {'smb2.eof' in fields}")
print(f"smb2.allocation_size in fields: {'smb2.allocation_size' in fields}")

cmd, used_fields = build_tshark_command(pcap, fields, reassembly=False)

print(f"\nUsed fields: {len(used_fields)}")
print(f"smb2.eof in used_fields: {'smb2.eof' in used_fields}")
print(f"smb2.allocation_size in used_fields: {'smb2.allocation_size' in used_fields}")

# Find position in command
try:
    eof_idx = cmd.index("-e") + cmd[cmd.index("-e"):].index("smb2.eof")
    print(f"\nsmb2.eof is at command position: {eof_idx}")
except ValueError:
    print("\nERROR: smb2.eof NOT in tshark command!")

try:
    alloc_idx = cmd.index("-e") + cmd[cmd.index("-e"):].index("smb2.allocation_size")
    print(f"smb2.allocation_size is at command position: {alloc_idx}")
except ValueError:
    print("ERROR: smb2.allocation_size NOT in tshark command!")

# Show sample of command around EOF field
eof_field_idx = used_fields.index("smb2.eof") if "smb2.eof" in used_fields else -1
if eof_field_idx >= 0:
    print(f"\nField index for smb2.eof: {eof_field_idx}")
    print(f"Surrounding fields: {used_fields[max(0, eof_field_idx-2):eof_field_idx+3]}")
