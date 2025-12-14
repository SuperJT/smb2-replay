#!/usr/bin/env python3
"""
Test Setup with PCAP Capture

This script performs setup operations while capturing PCAP traffic
to debug why files aren't being created properly.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid

from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def test_setup_with_pcap():
    """Test setup operations with PCAP capture."""
    print("Testing setup operations with PCAP capture...")

    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"

    # Start PCAP capture
    pcap_file = f"setup_debug_{int(time.time())}.pcap"
    print(f"Starting PCAP capture to {pcap_file}...")

    try:
        # Start tshark in background
        tshark_cmd = f"sudo tshark -i lo -w {pcap_file} -f 'port 445' -q"
        tshark_process = subprocess.Popen(
            tshark_cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )

        # Wait a moment for tshark to start
        time.sleep(2)

        print("PCAP capture started. Performing setup operations...")

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

        # Test 1: Create a directory
        test_dir = f"test_dir_pcap_{timestamp}"
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

        # Test 2: Create a file in the directory
        test_file = f"{test_dir}\\test_file_{timestamp}.txt"
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

        # Test 3: Create a file in root
        test_file_root = f"test_file_root_{timestamp}.txt"
        print(f"\nTest 3: Creating file '{test_file_root}' in root")

        try:
            file_open_root = Open(tree, test_file_root)
            file_open_root.create(
                impersonation_level=0,
                desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                share_access=0x00000001,  # FILE_SHARE_READ
                create_disposition=3,  # FILE_OPEN_IF
                create_options=0,  # No special options
            )
            print(f"✅ Created file: {test_file_root}")

            # Write some data
            test_data = f"Root test data written at {timestamp}".encode()
            bytes_written = file_open_root.write(test_data, 0)
            print(f"✅ Wrote {bytes_written} bytes to file")

            file_open_root.close()
        except SMBException as e:
            print(f"❌ Failed to create file '{test_file_root}': {e}")

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

        # Stop PCAP capture
        print("Stopping PCAP capture...")
        tshark_process.terminate()
        tshark_process.wait()

        print("✅ Test completed")
        print(f"📁 PCAP file saved: {pcap_file}")
        print("💡 Analyze the PCAP to see what SMB operations were actually performed")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        # Stop PCAP capture on error
        try:
            tshark_process.terminate()
        except:
            pass


if __name__ == "__main__":
    test_setup_with_pcap()
