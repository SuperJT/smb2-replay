#!/usr/bin/env python3
"""
Test Directory Creation with Different Dispositions

This script tests different create dispositions to understand the proper way
to create directories with smbprotocol.
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


def test_directory_dispositions():
    """Test directory creation with different dispositions."""
    print("Testing directory creation with different dispositions...")

    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"

    # Create dispositions
    dispositions = {
        1: "FILE_SUPERSEDE",
        2: "FILE_CREATE",
        3: "FILE_OPEN",
        4: "FILE_OPEN_IF",
        5: "FILE_OVERWRITE",
        6: "FILE_OVERWRITE_IF",
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
            print(
                f"\nTesting {disp_name} (value {disp_value}) with directory: {test_dir}"
            )

            try:
                dir_open = Open(tree, test_dir)
                dir_open.create(
                    impersonation_level=0,  # SECURITY_ANONYMOUS
                    desired_access=0x80000000,  # GENERIC_READ
                    file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=disp_value,
                    create_options=0x00000020,  # FILE_DIRECTORY_FILE
                )
                print(f"✅ Successfully created directory with {disp_name}")
                dir_open.close()

                # Try to create the same directory again to test behavior
                test_dir2 = f"test_disp_{disp_value}_again_{int(time.time())}"
                print(f"Testing {disp_name} again with: {test_dir2}")

                dir_open2 = Open(tree, test_dir2)
                dir_open2.create(
                    impersonation_level=0,
                    desired_access=0x80000000,
                    file_attributes=0x00000010,
                    share_access=0x00000001,
                    create_disposition=disp_value,
                    create_options=0x00000020,
                )
                print(f"✅ Successfully created second directory with {disp_name}")
                dir_open2.close()

            except SMBException as e:
                print(f"❌ Failed with {disp_name}: {e}")

        # Test nested directory creation with FILE_OPEN_IF
        print("\nTesting nested directory creation with FILE_OPEN_IF...")

        # First create parent directory
        parent_dir = f"parent_{int(time.time())}"
        try:
            parent_open = Open(tree, parent_dir)
            parent_open.create(
                impersonation_level=0,
                desired_access=0x80000000,
                file_attributes=0x00000010,
                share_access=0x00000001,
                create_disposition=4,  # FILE_OPEN_IF
                create_options=0x00000020,
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
                create_disposition=4,  # FILE_OPEN_IF
                create_options=0x00000020,
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
    test_directory_dispositions()
