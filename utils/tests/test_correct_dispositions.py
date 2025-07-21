#!/usr/bin/env python3
"""
Test Directory Creation with Correct Dispositions

This script tests directory creation with the correct create disposition values
from smbprotocol.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateDisposition
from smbprotocol.exceptions import SMBException
import uuid
import time

def test_correct_dispositions():
    """Test directory creation with correct dispositions."""
    print("Testing directory creation with correct dispositions...")
    
    # Configuration
    server_ip = "127.0.0.1"
    username = "jtownsen"
    password = "P@ssw0rd"
    share_name = "testshare"
    
    # Correct create dispositions
    dispositions = {
        CreateDisposition.FILE_CREATE: "FILE_CREATE",
        CreateDisposition.FILE_OPEN: "FILE_OPEN", 
        CreateDisposition.FILE_OPEN_IF: "FILE_OPEN_IF",
        CreateDisposition.FILE_OVERWRITE: "FILE_OVERWRITE",
        CreateDisposition.FILE_SUPERSEDE: "FILE_SUPERSEDE",
        CreateDisposition.FILE_OVERWRITE_IF: "FILE_OVERWRITE_IF"
    }
    
    try:
        # Setup connection
        print(f"Connecting to {server_ip}...")
        connection = Connection(uuid.uuid4(), server_ip, 445)
        connection.connect(timeout=5.0)
        
        print("Creating session...")
        session = Session(connection, username, password)
        session.connect()
        
        print(f"Connecting to tree: {share_name}")
        tree = TreeConnect(session, f"\\\\{server_ip}\\{share_name}")
        tree.connect()
        
        # Test each disposition
        for disp_value, disp_name in dispositions.items():
            test_dir = f"test_disp_{disp_value}_{int(time.time())}"
            print(f"\nTesting {disp_name} (value {disp_value}) with directory: {test_dir}")
            
            try:
                dir_open = Open(tree, test_dir)
                dir_open.create(
                    impersonation_level=0,  # SECURITY_ANONYMOUS
                    desired_access=0x80000000,  # GENERIC_READ
                    file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=disp_value,
                    create_options=0x00000020  # FILE_DIRECTORY_FILE
                )
                print(f"✅ Successfully created directory with {disp_name}")
                dir_open.close()
                
            except SMBException as e:
                print(f"❌ Failed with {disp_name}: {e}")
        
        # Test nested directory creation with FILE_OPEN_IF
        print(f"\nTesting nested directory creation with FILE_OPEN_IF...")
        
        # First create parent directory
        parent_dir = f"parent_{int(time.time())}"
        try:
            parent_open = Open(tree, parent_dir)
            parent_open.create(
                impersonation_level=0,
                desired_access=0x80000000,
                file_attributes=0x00000010,
                share_access=0x00000001,
                create_disposition=CreateDisposition.FILE_OPEN_IF,
                create_options=0x00000020
            )
            print(f"✅ Created parent directory: {parent_dir}")
            parent_open.close()
            
            # Now try to create nested directory
            nested_dir = f"{parent_dir}\\nested_{int(time.time())}"
            nested_open = Open(tree, nested_dir)
            nested_open.create(
                impersonation_level=0,
                desired_access=0x80000000,
                file_attributes=0x00000010,
                share_access=0x00000001,
                create_disposition=CreateDisposition.FILE_OPEN_IF,
                create_options=0x00000020
            )
            print(f"✅ Created nested directory: {nested_dir}")
            nested_open.close()
            
        except SMBException as e:
            print(f"❌ Failed nested directory creation: {e}")
        
        # Cleanup
        print("\nCleaning up...")
        try:
            tree.disconnect()
        except:
            pass
        try:
            session.disconnect()
        except:
            pass
        try:
            connection.disconnect()
        except:
            pass
        
        print("✅ Test completed")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_correct_dispositions() 