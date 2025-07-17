#!/usr/bin/env python3
"""
Simple test to verify impacket SMB usage pattern.
"""

import sys
sys.path.append('/home/jtownsen/bin/smbreplay/smbreplay_package')

from impacket.smbconnection import SMBConnection
from smbreplay.config import get_config

def test_impacket_usage():
    config = get_config()
    
    print("Testing impacket SMB usage pattern...")
    
    # Create connection
    conn = SMBConnection(config.get_server_ip(), config.get_server_ip(), sess_port=445)
    
    # Login
    conn.login(config.get_username(), config.get_password(), config.get_domain())
    print("✓ Login successful")
    
    # Connect to tree
    tid = conn.connectTree(config.get_tree_name())
    print(f"✓ Tree connect successful, tid: {tid}, type: {type(tid)}")
    
    # Try different approaches to list directory
    print("\nTrying different listPath approaches:")
    
    # Approach 1: Using tree name
    try:
        files = conn.listPath(config.get_tree_name(), '*')
        print(f"✓ listPath with tree name: {len(files)} files")
    except Exception as e:
        print(f"✗ listPath with tree name failed: {e}")
    
    # Approach 2: Using TID directly
    try:
        files = conn.listPath(tid, '*')
        print(f"✓ listPath with TID: {len(files)} files")
    except Exception as e:
        print(f"✗ listPath with TID failed: {e}")
    
    # Approach 3: Using TID as string
    try:
        files = conn.listPath(str(tid), '*')
        print(f"✓ listPath with TID as string: {len(files)} files")
    except Exception as e:
        print(f"✗ listPath with TID as string failed: {e}")
    
    conn.close()
    print("✓ Connection closed")

if __name__ == "__main__":
    test_impacket_usage()
