#!/usr/bin/env python3
"""
Test Directory vs File Creation

This script tests to understand why directory creation might be creating files
instead of directories.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def test_directory_vs_file():
    """Test directory vs file creation to understand the issue."""
    print("Testing directory vs file creation...")

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

        print("Creating session...")
        session = Session(connection, username, password)
        session.connect()

        print(f"Connecting to tree: {share_name}")
        tree = TreeConnect(session, f"\\\\{server_ip}\\{share_name}")
        tree.connect()

        timestamp = int(time.time())

        # Test 1: Create a directory with correct parameters
        test_dir = f"test_dir_{timestamp}"
        print(f"\nTest 1: Creating directory '{test_dir}' with directory parameters")

        try:
            dir_open = Open(tree, test_dir)
            dir_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0x00000020,  # FILE_DIRECTORY_FILE
            )
            print(f"✅ Created '{test_dir}' with directory parameters")
            dir_open.close()
        except SMBException as e:
            print(f"❌ Failed to create directory '{test_dir}': {e}")

        # Test 2: Create a file with file parameters
        test_file = f"test_file_{timestamp}"
        print(f"\nTest 2: Creating file '{test_file}' with file parameters")

        try:
            file_open = Open(tree, test_file)
            file_open.create(
                impersonation_level=0,
                desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0,  # No special options
            )
            print(f"✅ Created '{test_file}' with file parameters")
            file_open.close()
        except SMBException as e:
            print(f"❌ Failed to create file '{test_file}': {e}")

        # Test 3: Create something with mixed parameters (like our setup might be doing)
        test_mixed = f"test_mixed_{timestamp}"
        print(f"\nTest 3: Creating '{test_mixed}' with mixed parameters")

        try:
            mixed_open = Open(tree, test_mixed)
            mixed_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ only
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0,  # No FILE_DIRECTORY_FILE
            )
            print(f"✅ Created '{test_mixed}' with mixed parameters")
            mixed_open.close()
        except SMBException as e:
            print(f"❌ Failed to create '{test_mixed}': {e}")

        # Test 4: List what we created
        print("\nTest 4: Listing created items...")
        try:
            # Use smbprotocol to list files
            from smbprotocol.file_info import FileDirectoryInformation, FileInfoClass

            # Open root directory
            root_open = Open(tree, "")
            root_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0x00000020,  # FILE_DIRECTORY_FILE
            )

            # Query directory
            query_info = root_open.query_directory(
                FileInfoClass.FILE_DIRECTORY_INFORMATION, pattern="test_*"
            )

            print("Created items:")
            for info in query_info:
                file_info = FileDirectoryInformation()
                file_info.unpack(info)
                item_type = "DIR" if file_info.file_attributes & 0x00000010 else "FILE"
                print(f"  {item_type}: {file_info.file_name.decode('utf-16-le')}")

            root_open.close()

        except Exception as e:
            print(f"❌ Failed to list items: {e}")

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
    test_directory_vs_file()
