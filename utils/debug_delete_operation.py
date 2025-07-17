#!/usr/bin/env python3
"""
Debug the TID handling issue for deleteFile operation.
"""

import sys
sys.path.append('/home/jtownsen/bin/smbreplay/smbreplay_package')

from impacket.smbconnection import SMBConnection
from smbreplay.config import get_config

def debug_file_operations():
    config = get_config()
    
    print("Debugging file operations...")
    
    # Create connection
    conn = SMBConnection(config.get_server_ip(), config.get_server_ip(), sess_port=445)
    
    # Login
    conn.login(config.get_username(), config.get_password(), config.get_domain())
    print("✓ Login successful")
    
    # Connect to tree
    tid = conn.connectTree(config.get_tree_name())
    print(f"✓ Tree connect successful, tid: {tid}, type: {type(tid)}")
    
    test_filename = 'debug_test.txt'
    
    try:
        # Create file
        print(f"Creating file: {test_filename}")
        fid = conn.createFile(tid, test_filename, desiredAccess=0x80000000)
        print(f"✓ File create successful, fid: {fid}, type: {type(fid)}")
        
        # Close file
        print(f"Closing file: {test_filename}")
        conn.closeFile(tid, fid)
        print("✓ File close successful")
        
        # Try different approaches to delete
        print("\nTesting different delete approaches:")
        
        # Approach 1: Direct TID
        try:
            print(f"Approach 1: deleteFile(tid={tid}, filename='{test_filename}')")
            conn.deleteFile(tid, test_filename)
            print("✓ Delete with direct TID successful")
        except Exception as e:
            print(f"✗ Delete with direct TID failed: {e}")
            
        # Approach 2: TID as string
        try:
            print(f"Approach 2: deleteFile(tid='{tid}', filename='{test_filename}')")
            conn.deleteFile(str(tid), test_filename)
            print("✓ Delete with TID as string successful")
        except Exception as e:
            print(f"✗ Delete with TID as string failed: {e}")
            
        # Approach 3: Tree name
        try:
            print(f"Approach 3: deleteFile(tree_name='{config.get_tree_name()}', filename='{test_filename}')")
            conn.deleteFile(config.get_tree_name(), test_filename)
            print("✓ Delete with tree name successful")
        except Exception as e:
            print(f"✗ Delete with tree name failed: {e}")
            
    except Exception as e:
        print(f"✗ Operation failed: {e}")
    
    conn.close()
    print("✓ Connection closed")

if __name__ == "__main__":
    debug_file_operations()
