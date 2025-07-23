#!/usr/bin/env python3
"""
Test Directory Listing

This script tests directory listing to see what was actually created.
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

def test_directory_listing():
    """Test directory listing to see what was created."""
    print("Testing directory listing...")
    
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
        
        # List root directory
        print("Listing root directory:")
        try:
            root_open = Open(tree, "")
            root_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,
                create_disposition=1,  # FILE_OPEN
                create_options=0x00000020  # FILE_DIRECTORY_FILE
            )
            
            # List contents
            files = root_open.query_directory("*", 1)  # FileNamesInformationClass = 1
            for file_info in files:
                name = file_info['file_name'].get_value().decode('utf-16-le')
                if name not in ['.', '..']:
                    print(f"  - {name}")
            
            root_open.close()
        except SMBException as e:
            print(f"❌ Failed to list root directory: {e}")
        
        # Try to list the new_test_dir
        print("\nTrying to list new_test_dir:")
        try:
            dir_open = Open(tree, "new_test_dir")
            dir_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,
                create_disposition=1,  # FILE_OPEN
                create_options=0x00000020  # FILE_DIRECTORY_FILE
            )
            
            # List contents
            files = dir_open.query_directory("*", 1)  # FileNamesInformationClass = 1
            print("  Directory contents:")
            for file_info in files:
                name = file_info['file_name'].get_value().decode('utf-16-le')
                if name not in ['.', '..']:
                    print(f"    - {name}")
            
            dir_open.close()
        except SMBException as e:
            print(f"❌ Failed to list new_test_dir: {e}")
        
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
        
        
    except SMBException as e:
        print(f"❌ SMB Error: {e}")
        raise
    except Exception as e:
        print(f"❌ Error: {e}")
        raise

if __name__ == "__main__":
    success = test_directory_listing()
    sys.exit(0 if success else 1) 