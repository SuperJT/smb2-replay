#!/usr/bin/env python3
"""
Cleanup Test Files

This script cleans up test files from the SMB server.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def cleanup_test_files():
    """Clean up test files from the SMB server."""
    print("Cleaning up test files from SMB server...")

    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"

    # Files to clean up
    files_to_delete = [
        "cache_volume",  # This was created as a file instead of directory
        "desktop.ini",  # Test file
        "TestCopyFolder.tmp",  # Test file
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

        # Delete files
        for filename in files_to_delete:
            try:
                print(f"Deleting: {filename}")
                file_open = Open(tree, filename)
                file_open.create(
                    impersonation_level=0,
                    desired_access=0x00010000,  # DELETE
                    file_attributes=0,
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=1,  # FILE_OPEN (don't create if missing)
                    create_options=0,
                )

                # Close to delete
                file_open.close()
                print(f"✅ Deleted: {filename}")

            except SMBException as e:
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    print(f"⚠️  File not found: {filename}")
                else:
                    print(f"❌ Failed to delete {filename}: {e}")

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

        print("✅ Cleanup completed")

    except Exception as e:
        print(f"❌ Cleanup failed: {e}")


if __name__ == "__main__":
    cleanup_test_files()
