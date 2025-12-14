#!/usr/bin/env python3
"""
Test Correct Create Options for Directory Creation

This script tests directory creation with the correct create options.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import CreateOptions, Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def test_correct_create_options():
    """Test directory creation with correct create options."""
    print("Testing directory creation with correct create options...")

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

        # Test 1: Create directory with correct create options
        test_dir = f"test_dir_correct_{timestamp}"
        print(f"\nTest 1: Creating directory '{test_dir}' with correct create options")

        try:
            dir_open = Open(tree, test_dir)
            dir_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=CreateOptions.FILE_DIRECTORY_FILE,  # Correct value: 1
            )
            print(f"✅ Created '{test_dir}' with correct create options")
            dir_open.close()
        except SMBException as e:
            print(f"❌ Failed to create directory '{test_dir}': {e}")

        # Test 2: Create directory with wrong create options (what we were using)
        test_dir_wrong = f"test_dir_wrong_{timestamp}"
        print(
            f"\nTest 2: Creating directory '{test_dir_wrong}' with wrong create options"
        )

        try:
            dir_open_wrong = Open(tree, test_dir_wrong)
            dir_open_wrong.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0x00000020,  # Wrong value: 32
            )
            print(f"✅ Created '{test_dir_wrong}' with wrong create options")
            dir_open_wrong.close()
        except SMBException as e:
            print(f"❌ Failed to create directory '{test_dir_wrong}': {e}")

        # Test 3: Create file for comparison
        test_file = f"test_file_{timestamp}"
        print(f"\nTest 3: Creating file '{test_file}' for comparison")

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
        print(
            "\n💡 Check the directory listing to see if directories were created correctly"
        )

    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    test_correct_create_options()
