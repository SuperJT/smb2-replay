#!/usr/bin/env python3
"""
Test Simple Directory Creation

This script tests basic directory creation to understand the SMB server behavior.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.exceptions import SMBException
import uuid

def test_simple_directory():
    """Test simple directory creation."""
    print("Testing simple directory creation...")
    
    # Configuration
    server_ip = "127.0.0.1"
    username = "jtownsen"
    password = "P@ssw0rd"
    share_name = "testshare"
    
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
        
        # Test 1: Create a simple directory
        test_dir = "simple_test"
        print(f"Creating simple directory: {test_dir}")
        
        try:
            dir_open = Open(tree, test_dir)
            dir_open.create(
                impersonation_level=0,
                desired_access=0x80000000,
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,
                create_disposition=2,  # FILE_CREATE
                create_options=0x00000020  # FILE_DIRECTORY_FILE
            )
            print(f"✅ Created directory: {test_dir}")
            dir_open.close()
        except SMBException as e:
            print(f"❌ Failed to create directory {test_dir}: {e}")
        
        # Test 2: Try to create a nested directory
        nested_dir = "simple_test\\nested"
        print(f"Creating nested directory: {nested_dir}")
        
        try:
            nested_open = Open(tree, nested_dir)
            nested_open.create(
                impersonation_level=0,
                desired_access=0x80000000,
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,
                create_disposition=2,  # FILE_CREATE
                create_options=0x00000020  # FILE_DIRECTORY_FILE
            )
            print(f"✅ Created nested directory: {nested_dir}")
            nested_open.close()
        except SMBException as e:
            print(f"❌ Failed to create nested directory {nested_dir}: {e}")
        
        # Test 3: Try to create a file in the nested directory
        test_file = "simple_test\\nested\\test.txt"
        print(f"Creating file in nested directory: {test_file}")
        
        try:
            file_open = Open(tree, test_file)
            file_open.create(
                impersonation_level=0,
                desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                share_access=0x00000001,
                create_disposition=1,  # FILE_OPEN_IF
                create_options=0
            )
            print(f"✅ Created file: {test_file}")
            file_open.close()
        except SMBException as e:
            print(f"❌ Failed to create file {test_file}: {e}")
        
        # Cleanup
        print("Cleaning up...")
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
        
        return True
        
    except SMBException as e:
        print(f"❌ SMB Error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    success = test_simple_directory()
    sys.exit(0 if success else 1) 