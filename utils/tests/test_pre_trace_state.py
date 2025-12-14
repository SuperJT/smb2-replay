#!/usr/bin/env python3
"""
Test Pre-Trace State Setup

This script tests the improved pre-trace state setup functionality
to verify that directories and files are created in the correct order.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import uuid

import pytest
from smbprotocol.connection import Connection
from smbprotocol.exceptions import SMBException
from smbprotocol.open import Open
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect


def test_pre_trace_state():
    """Test pre-trace state setup with sample operations."""
    print("Testing pre-trace state setup...")

    # Configuration
    server_ip = "127.0.0.1"
    username = os.environ.get("SMB_USERNAME", "testuser")
    password = os.environ.get("SMB_PASSWORD", "testpass")
    share_name = "testshare"

    # Sample operations that would trigger pre-trace state setup
    sample_operations = [
        {
            "smb2.filename": "new_test_dir\\subdir1\\file1.txt",
            "smb2.cmd": "5",
            "smb2.flags.response": "True",
            "smb2.create.action": "FILE_CREATED",
        },
        {
            "smb2.filename": "new_test_dir\\subdir2\\file2.txt",
            "smb2.cmd": "5",
            "smb2.flags.response": "True",
            "smb2.create.action": "FILE_CREATED",
        },
        {
            "smb2.filename": "new_test_dir\\subdir1\\nested\\config.ini",
            "smb2.cmd": "5",
            "smb2.flags.response": "False",  # This is a request, not response
            "smb2.create.action": "FILE_CREATED",
        },
        {
            "smb2.filename": "N/A",  # Should be ignored
            "smb2.cmd": "5",
            "smb2.flags.response": "True",
            "smb2.create.action": "FILE_CREATED",
        },
    ]

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

            if (
                "SMB encryption is required but the connection does not support it"
                in str(e)
            ):
                pytest.skip(
                    "Skipping test: SMB encryption is required but the connection does not support it (likely a client/server negotiation issue)"
                )
            print(f"❌ SMB Error during session.connect(): {e}")
            traceback.print_exc()
            raise

        print(f"Connecting to tree: {share_name}")
        tree = TreeConnect(session, f"\\\\{server_ip}\\{share_name}")
        tree.connect()

        # Test the pre-trace state setup logic
        print("Testing pre-trace state setup logic...")

        # Collect all valid paths and created files
        all_paths = set()
        created_files = set()
        existing_files = set()

        for op in sample_operations:
            filename = op.get("smb2.filename", "")
            if filename and filename not in [".", "..", "N/A", ""]:
                all_paths.add(filename)
            if (
                op.get("smb2.cmd") == "5"
                and op.get("smb2.flags.response") == "True"
                and op.get("smb2.create.action") == "FILE_CREATED"
            ):
                created_files.add(filename)
            elif (
                op.get("smb2.cmd") == "5"
                and op.get("smb2.flags.response") == "True"
                and op.get("smb2.create.action") == "FILE_OPENED"
            ):
                existing_files.add(filename)

        print(f"Valid paths: {all_paths}")
        print(f"Created files: {created_files}")
        print(f"Existing files: {existing_files}")

        # Normalize paths and extract directories
        directories = set()
        normalized_paths = set()

        for path in all_paths:
            # Normalize path separators (handle both \ and /)
            normalized_path = path.replace("/", "\\")
            normalized_paths.add(normalized_path)

            # Extract parent directories for all paths with multiple parts
            parts = normalized_path.split("\\")
            if len(parts) > 1:
                for i in range(1, len(parts)):
                    dir_path = "\\".join(parts[:i])
                    if dir_path:
                        directories.add(dir_path)

        print(
            f"Found {len(directories)} directories and {len(normalized_paths)} files to process"
        )
        print(
            f"Directories to create: {sorted(directories, key=lambda x: (x.count('\\'), x))}"
        )
        print(f"Normalized paths: {normalized_paths}")

        # Create directories in proper order (parents first)
        created_dirs = set()
        sorted_dirs = sorted(directories, key=lambda x: (x.count("\\"), x))

        for dir_path in sorted_dirs:
            # Create each directory along the path step by step
            parts = dir_path.split("\\")
            current_path = ""

            for i, part in enumerate(parts):
                if i == 0:
                    current_path = part
                else:
                    current_path = current_path + "\\" + part

                # Skip if we already created this directory
                if current_path in created_dirs:
                    continue

                try:
                    print(f"Creating directory: {current_path}")
                    dir_open = Open(tree, current_path)
                    dir_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x80000000,  # GENERIC_READ
                        file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=2,  # FILE_CREATE
                        create_options=0x00000020,  # FILE_DIRECTORY_FILE
                    )
                    created_dirs.add(current_path)
                    print(f"✅ Created directory: {current_path}")
                    dir_open.close()
                except SMBException as e:
                    if "STATUS_OBJECT_NAME_COLLISION" not in str(e):
                        print(f"❌ Failed to create directory {current_path}: {e}")
                        # Break out of the loop for this path since we can't create nested dirs
                        break
                    else:
                        print(f"⚠️  Directory already exists: {current_path}")
                        created_dirs.add(current_path)

        # Create files that existed before the selected operations
        files_created = 0
        for path in normalized_paths:
            if path not in directories and path not in created_files:
                try:
                    print(f"Creating file: {path}")
                    file_open = Open(tree, path)
                    file_open.create(
                        impersonation_level=0,  # SECURITY_ANONYMOUS
                        desired_access=0x80000000
                        | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                        file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                        share_access=0x00000001,  # FILE_SHARE_READ
                        create_disposition=1,  # FILE_OPEN_IF
                        create_options=0,  # No special options
                    )
                    files_created += 1
                    print(f"✅ Created file: {path}")
                    file_open.close()
                except SMBException as e:
                    print(f"❌ Failed to create file {path}: {e}")

        print("✅ Pre-trace state setup complete:")
        print(f"  - {len(created_dirs)} directories created/exist")
        print(f"  - {files_created} pre-existing files created")
        print(f"  - {len(created_files)} files will be created during replay")
        print(f"  - {len(existing_files)} files already exist and will be opened")

        if len(created_dirs) < len(directories):
            print(
                f"⚠️  Only {len(created_dirs)}/{len(directories)} directories could be created"
            )
            print(
                "⚠️  Some nested directories may not exist - replay may fail for those paths"
            )
            print(
                "ℹ️  Consider using a different SMB server or share that supports nested directory creation"
            )

        # Validate file system structure
        validate_file_system_structure(normalized_paths, created_dirs)

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


def validate_file_system_structure(paths: set, created_dirs: set):
    """Validate that the file system structure is ready for replay."""
    print("Validating file system structure for replay...")

    missing_dirs = set()
    accessible_paths = 0

    for path in paths:
        # Check if the parent directory exists for each path
        parts = path.split("\\")
        if len(parts) > 1:
            parent_dir = "\\".join(parts[:-1])
            if parent_dir not in created_dirs:
                missing_dirs.add(parent_dir)
            else:
                accessible_paths += 1
        else:
            # File in root directory
            accessible_paths += 1

    if missing_dirs:
        print(f"⚠️  Missing directories for {len(missing_dirs)} paths:")
        for missing_dir in sorted(missing_dirs):
            print(f"    - {missing_dir}")
        print(
            f"⚠️  Only {accessible_paths}/{len(paths)} paths will be accessible during replay"
        )
    else:
        print(f"✅ All {len(paths)} paths are accessible for replay")


if __name__ == "__main__":
    success = test_pre_trace_state()
    sys.exit(0 if success else 1)
