#!/usr/bin/env python3
"""
Force Cleanup Test Files

This script forcefully cleans up test files from the SMB server.
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

def force_cleanup():
    """Force clean up test files from the SMB server."""
    print("Force cleaning up test files from SMB server...")
    
    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"
    
    # Files to clean up
    files_to_delete = [
        "cache_volume",
        "desktop.ini",
        "TestCopyFolder.tmp"
    ]
    
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
        
        # Delete files with different approaches
        for filename in files_to_delete:
            print(f"\nTrying to delete: {filename}")
            
            # Try as file first
            try:
                print(f"  Attempting to delete as file...")
                file_open = Open(tree, filename)
                file_open.create(
                    impersonation_level=0,
                    desired_access=0x00010000,  # DELETE
                    file_attributes=0,
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=3,  # FILE_OPEN_IF
                    create_options=0
                )
                file_open.close()
                print(f"  ✅ Deleted as file: {filename}")
                continue
                
            except SMBException as e:
                print(f"  ❌ Failed to delete as file: {e}")
            
            # Try as directory
            try:
                print(f"  Attempting to delete as directory...")
                dir_open = Open(tree, filename)
                dir_open.create(
                    impersonation_level=0,
                    desired_access=0x00010000,  # DELETE
                    file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=3,  # FILE_OPEN_IF
                    create_options=1  # FILE_DIRECTORY_FILE
                )
                dir_open.close()
                print(f"  ✅ Deleted as directory: {filename}")
                continue
                
            except SMBException as e:
                print(f"  ❌ Failed to delete as directory: {e}")
            
            print(f"  ⚠️  Could not delete: {filename}")
        
        # Cleanup
        print("\nCleaning up connection...")
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
        
        print("✅ Force cleanup completed")
        
    except Exception as e:
        print(f"❌ Force cleanup failed: {e}")

if __name__ == "__main__":
    force_cleanup() 