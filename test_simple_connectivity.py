#!/usr/bin/env python3
"""
Simple test to isolate connectivity issues.
"""

import sys
import os
import socket

print("Starting simple connectivity test...")

# Test 1: Basic imports
try:
    print("Testing imports...")
    sys.path.append('/Users/jtownsen/bin/smb2-replay/smbreplay_package')
    print("✓ Path added")
    
    from smbreplay.config import get_config
    print("✓ Config module imported")
    
    config = get_config()
    print("✓ Config loaded")
    
    print(f"Server IP: {config.get_server_ip()}")
    print(f"Domain: {config.get_domain()}")
    print(f"Username: {config.get_username()}")
    print(f"Tree: {config.get_tree_name()}")
    
except Exception as e:
    print(f"✗ Import/config error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 2: Socket connectivity
try:
    print("\nTesting socket connectivity...")
    server_ip = config.get_server_ip()
    sock = socket.create_connection((server_ip, 445), timeout=5)
    sock.close()
    print(f"✓ Socket connection to {server_ip}:445 successful")
except Exception as e:
    print(f"✗ Socket connection failed: {e}")
    sys.exit(1)

# Test 3: Try impacket import separately
try:
    print("\nTesting impacket import...")
    from impacket.smbconnection import SMBConnection
    print("✓ impacket.smbconnection imported")
except Exception as e:
    print(f"✗ impacket import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 4: Try creating SMBConnection object
try:
    print("\nTesting SMBConnection creation...")
    conn = SMBConnection(server_ip, server_ip, sess_port=445)
    print("✓ SMBConnection object created")
    
    # Don't try to login yet, just test object creation
    print("✓ Simple connectivity test passed")
    
except Exception as e:
    print(f"✗ SMBConnection creation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\nAll simple tests passed!")
