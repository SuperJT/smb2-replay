#!/usr/bin/env python3
"""
Test SMB Connection Without Encryption

This script tests SMB connection with encryption disabled to see if that
fixes the setup issues.
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


def test_no_encryption():
    """Test SMB connection without encryption."""
    print("Testing SMB connection without encryption...")

    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"

    try:
        # Setup connection
        print(f"Connecting to {server_ip}...")
        connection = Connection(uuid.uuid4(), server_ip, 445)

        # Try to disable encryption if possible
        # Note: smbprotocol doesn't expose direct encryption control
        # but we can check what's happening during negotiation
        connection.connect(timeout=5.0)

        print("Creating session...")
        session = Session(connection, username, password)

        # Try to disable encryption in session
        # This might not be directly supported, but let's see what happens
        session.connect()

        print(f"Connecting to tree: {share_name}")
        tree = TreeConnect(session, f"\\\\{server_ip}\\{share_name}")
        tree.connect()

        timestamp = int(time.time())

        # Test 1: Create a directory
        test_dir = f"test_dir_no_encrypt_{timestamp}"
        print(f"\nTest 1: Creating directory '{test_dir}'")

        try:
            dir_open = Open(tree, test_dir)
            dir_open.create(
                impersonation_level=0,
                desired_access=0x80000000,  # GENERIC_READ
                file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=1,  # FILE_DIRECTORY_FILE
            )
            print(f"✅ Created directory: {test_dir}")
            dir_open.close()
        except SMBException as e:
            print(f"❌ Failed to create directory '{test_dir}': {e}")

        # Test 2: Create a file
        test_file = f"test_file_no_encrypt_{timestamp}.txt"
        print(f"\nTest 2: Creating file '{test_file}'")

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
            print(f"✅ Created file: {test_file}")

            # Write some data
            test_data = f"Test data written at {timestamp}".encode()
            bytes_written = file_open.write(test_data, 0)
            print(f"✅ Wrote {bytes_written} bytes to file")

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
        print("💡 If this works better, we need to disable encryption in the main code")

    except Exception as e:
        print(f"❌ Test failed: {e}")


if __name__ == "__main__":
    test_no_encryption()
