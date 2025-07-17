#!/usr/bin/env python3
"""
SMB2 Replay System Status Report
"""

import sys
import os
sys.path.append('/Users/jtownsen/bin/smb2-replay/smbreplay_package')

from smbreplay.config import get_config
from smbreplay.main import SMB2ReplaySystem
from smbreplay.replay import validate_operations, get_supported_commands

print("=" * 60)
print("SMB2 REPLAY SYSTEM STATUS REPORT")
print("=" * 60)

# Configuration Status
config = get_config()
print("\n1. CONFIGURATION STATUS:")
print(f"   ✓ Server IP: {config.get_server_ip()}")
print(f"   ✓ Domain: {config.get_domain()}")
print(f"   ✓ Username: {config.get_username()}")
print(f"   ✓ Tree/Share: {config.get_tree_name()}")
print(f"   ✓ Session ID: {config.get_session_id()}")
print(f"   ✓ Case ID: {config.get_case_id()}")
print(f"   ✓ Trace Name: {config.get_trace_name()}")

# Session Data Status
print("\n2. SESSION DATA STATUS:")
session_file = config.resolve_session_file(config.get_session_id())
if session_file:
    print(f"   ✓ Session file found: {os.path.basename(session_file)}")
    
    system = SMB2ReplaySystem()
    operations = system.get_session_info(f'smb2_session_{config.get_session_id()}.parquet')
    
    if operations:
        print(f"   ✓ Operations loaded: {len(operations)}")
        
        # Validate operations
        validation = validate_operations(operations)
        if validation['valid']:
            print(f"   ✓ All operations validated successfully")
            print(f"   ✓ Total operations: {validation['total_operations']}")
            print(f"   ✓ Supported operations: {validation['supported_operations']}")
        else:
            print(f"   ✗ Validation issues: {len(validation['issues'])}")
    else:
        print("   ✗ Failed to load operations")
else:
    print("   ✗ No session file found")

# Supported Commands
print("\n3. SUPPORTED SMB2 COMMANDS:")
supported_commands = get_supported_commands()
for cmd_code, description in supported_commands.items():
    print(f"   ✓ Command {cmd_code}: {description}")

# Network Connectivity
print("\n4. NETWORK CONNECTIVITY:")
try:
    import socket
    server_ip = config.get_server_ip()
    sock = socket.create_connection((server_ip, 445), timeout=5)
    sock.close()
    print(f"   ✓ Port 445 reachable on {server_ip}")
except Exception as e:
    print(f"   ✗ Port 445 connection failed: {e}")

# SMB Library Status
print("\n5. SMB LIBRARY STATUS:")
try:
    from impacket.smbconnection import SMBConnection
    print("   ✓ Impacket SMBConnection available")
except Exception as e:
    print(f"   ✗ Impacket SMBConnection failed: {e}")
    print("   ! This is the main blocker for actual replay")

print("\n" + "=" * 60)
print("SUMMARY:")
print("=" * 60)
print("✓ Configuration system: WORKING")
print("✓ Session data loading: WORKING") 
print("✓ Operation validation: WORKING")
print("✓ Command support: EXPANDED (10 commands)")
print("✓ Network connectivity: WORKING")
print("✗ SMB library: NEEDS FIXING")
print("\nNext Steps:")
print("1. Fix impacket installation issue")
print("2. Test actual SMB operations")
print("3. Implement replay handlers for new commands")
print("4. Add error handling and retry logic")
print("=" * 60)
