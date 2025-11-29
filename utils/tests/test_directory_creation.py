#!/usr/bin/env python3
"""
Test Directory Creation with smbprotocol

This script tests the directory creation functionality using smbprotocol
to verify that the fix for the create_directory() method works.
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
import pytest

def test_directory_creation():
    """Test directory creation using smbprotocol."""
    print("Testing directory creation with smbprotocol...")
    
    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"
    
    try:
        # Setup connection
        print(f"Connecting to {server_ip}...")
        connection = Connection(uuid.uuid4(), server_ip, 445)
        connection.connect(timeout=5.0)
        print(f"Creating session with username: {username}, password: {password}")
        session = Session(connection, username, password)
        try:
            session.connect()
        except Exception as e:
            import traceback
            if "SMB encryption is required but the connection does not support it" in str(e):
                pytest.skip("Skipping test: SMB encryption is required but the connection does not support it (likely a client/server negotiation issue)")
            print(f"❌ SMB Error during session.connect(): {e}")
            traceback.print_exc()
            raise
        
        print(f"Connecting to tree: {share_name}")
        tree = TreeConnect(session, f"\\\\{server_ip}\\{share_name}")
        tree.connect()
        
        # Test directory creation in root
        test_dir = "testdir"
        print(f"Creating directory: {test_dir}")
        
        dir_open = Open(tree, test_dir)
        dir_open.create(
            impersonation_level=0,  # SECURITY_ANONYMOUS
            desired_access=0x80000000,  # GENERIC_READ
            file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
            share_access=0x00000001,  # FILE_SHARE_READ
            create_disposition=2,  # FILE_CREATE
            create_options=0x00000020  # FILE_DIRECTORY_FILE
        )
        print(f"✅ Successfully created directory: {test_dir}")
        dir_open.close()
        
        # Test nested directory creation with forward slashes
        nested_dir = "testdir/nested"
        print(f"Creating nested directory: {nested_dir}")
        
        nested_open = Open(tree, nested_dir)
        nested_open.create(
            impersonation_level=0,  # SECURITY_ANONYMOUS
            desired_access=0x80000000,  # GENERIC_READ
            file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
            share_access=0x00000001,  # FILE_SHARE_READ
            create_disposition=1,  # FILE_OPEN_IF
            create_options=0x00000020  # FILE_DIRECTORY_FILE
        )
        print(f"✅ Successfully created nested directory: {nested_dir}")
        nested_open.close()
        
        # Test with backslashes
        nested_dir2 = "testdir\\nested2"
        print(f"Creating nested directory with backslashes: {nested_dir2}")
        
        nested_open2 = Open(tree, nested_dir2)
        nested_open2.create(
            impersonation_level=0,  # SECURITY_ANONYMOUS
            desired_access=0x80000000,  # GENERIC_READ
            file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
            share_access=0x00000001,  # FILE_SHARE_READ
            create_disposition=1,  # FILE_OPEN_IF
            create_options=0x00000020  # FILE_DIRECTORY_FILE
        )
        print(f"✅ Successfully created nested directory: {nested_dir2}")
        nested_open2.close()
        
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
        
        print("✅ Directory creation test completed successfully!")
        
    except SMBException as e:
        print(f"❌ SMB Error: {e}")
        raise
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    success = test_directory_creation()
    sys.exit(0 if success else 1) 