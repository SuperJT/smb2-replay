#!/usr/bin/env python3
"""
Test SMB server connectivity and basic operations using smbprotocol.
"""

import sys
import os
import socket
import uuid
import pytest
from typing import Optional

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

from smbprotocol.open import (
    Open, 
    ImpersonationLevel, 
    FilePipePrinterAccessMask, 
    FileAttributes, 
    ShareAccess, 
    CreateDisposition, 
    CreateOptions, 
    FileInformationClass
)
from smbprotocol.file_info import FileDispositionInformation


import logging
logging.basicConfig(level=logging.INFO)

from smbreplay.config import get_config

def test_basic_connectivity(server_ip: str = "127.0.0.1", port: int = 445, timeout: int = 5):
    """Test basic TCP connectivity to SMB port."""
    print(f"Testing basic connectivity to {server_ip}:{port}...")
    try:
        sock = socket.create_connection((server_ip, port), timeout=timeout)
        sock.close()
        print("✓ Port 445 is reachable")
        assert True
    except Exception as e:
        print(f"✗ Port 445 connection failed: {e}")
        raise

def test_smb_login(server_ip: str = "127.0.0.1", username: str = "test", password: str = "test") -> Optional[tuple[Connection, Session]]:
    """Test SMB login and return (Connection, Session) if successful."""
    print(f"Testing SMB login to {server_ip}...")
    print(f"  [DEBUG] Username: {username}")
    print(f"  [DEBUG] Password: {password}")
    try:
        conn = Connection(uuid.uuid4(), server_ip, 445)
        conn.connect(timeout=5.0)
        session = Session(conn, username, password)
        session.connect()
        print("✓ SMB login successful")
        return conn, session
    except Exception as e:
        import traceback
        print(f"✗ SMB login failed: {e}")
        traceback.print_exc()
        return None

def test_tree_connect(session: Session = None, server_ip: str = "127.0.0.1", share_name: str = "testshare") -> Optional[TreeConnect]:
    """Test tree connection and return TreeConnect if successful."""
    if session is None:
        pytest.skip("Session not available for tree connect test")
    
    # Use share_name from config if not provided
    if not share_name:
        config = get_config()
        share_name = config.get_tree_name()
    share_path = f"\\{server_ip}\\{share_name}"
    print(f"Testing tree connect to share '{share_name}'...")
    print(f"  [DEBUG] Share path: {share_path}")
    print(f"  [DEBUG] Session username: {getattr(session, 'username', 'unknown')}")
    try:
        tree = TreeConnect(session, share_path)
        print(f"  [DEBUG] TreeConnect object created: {tree}")
        tree.connect()
        print(f"✓ Tree connect successful")
        return tree
    except Exception as e:
        print(f"✗ Tree connect failed: {e}")
        return None

def test_directory_listing(tree: TreeConnect = None, path: str = "") -> bool:
    """Test directory listing."""
    if tree is None:
        pytest.skip("Tree not available for directory listing test")
    
    print(f"Testing directory listing for path '{path or '.'}'...")
    try:
        handle = Open(tree, path or "")
        handle.create(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ,
            FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
            ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_DIRECTORY_FILE
        )
        entries = handle.query_directory("*", FileInformationClass.FILE_NAMES_INFORMATION)
        names = [e['file_name'].get_value().decode('utf-16-le') for e in entries]
        print(f"✓ Directory listing successful, found {len(names)} items")
        for i, name in enumerate(names[:5]):
            print(f"  {name}")
        if len(names) > 5:
            print(f"  ... and {len(names) - 5} more items")
        handle.close()
        return True
    except Exception as e:
        print(f"✗ Directory listing failed: {e}")
        return False

def test_file_operations(tree: TreeConnect = None, test_filename: str = 'smb2_replay_test.txt') -> bool:
    """Test basic file operations."""
    if tree is None:
        pytest.skip("Tree not available for file operations test")
    
    print(f"Testing file operations with '{test_filename}'...")
    try:
        # Create file
        print(f"  Creating file: {test_filename}")
        handle = Open(tree, test_filename)
        try:
            handle.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.GENERIC_READ | FilePipePrinterAccessMask.GENERIC_WRITE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE
            )
            print(f"  ✓ File create successful")
        finally:
            handle.close()
            print(f"  ✓ File close successful")

        # Delete file
        print(f"  Deleting test file: {test_filename}")
        handle = Open(tree, test_filename)
        try:
            handle.create(
                ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.DELETE,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE | CreateOptions.FILE_DELETE_ON_CLOSE
            )
        finally:
            handle.close()
            print(f"  ✓ File delete successful")
        return True
    except Exception as e:
        print(f"✗ File operations failed: {e}")
        return False

def main():
    """Main test function."""
    print("=" * 60)
    print("SMB2 Replay Server Connectivity Test (smbprotocol)")
    print("=" * 60)
    config = get_config()
    print("\nConfiguration:")
    print(f"  Server IP: {config.get_server_ip()}")
    print(f"  Domain: {config.get_domain()}")
    print(f"  Username: {config.get_username()}")
    print(f"  Password: {'*' * len(config.get_password())}")
    print(f"  Tree/Share: {config.get_tree_name()}")
    print(f"  Max Wait: {config.get_max_wait()}s")
    print("\n" + "=" * 60)
    print("Running connectivity tests...")
    print("=" * 60)
    # Test 1: Basic connectivity
    if not test_basic_connectivity(config.get_server_ip()):
        print("\n✗ Basic connectivity test failed. Check server IP and network.")
        return False
    # Test 2: SMB login
    login_result = test_smb_login(
        config.get_server_ip(),
        config.get_username(),
        config.get_password()
    )
    if not login_result:
        print("\n✗ SMB login test failed. Check credentials and domain.")
        return False
    conn, session = login_result
    # Test 3: Tree connect
    tree = test_tree_connect(session, config.get_server_ip(), config.get_tree_name())
    if not tree:
        print(f"\n✗ Tree connect test failed. Check if share '{config.get_tree_name()}' exists.")
        conn.disconnect()
        session.disconnect()
        return False
    # Test 4: Directory listing
    if not test_directory_listing(tree):
        print("\n✗ Directory listing test failed. Check share permissions.")
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    # Test 5: File operations
    file_ops_success = test_file_operations(tree)
    if not file_ops_success:
        print("\n✗ File operations test failed. Check write permissions.")
        tree.disconnect()
        session.disconnect()
        conn.disconnect()
        return False
    # Clean up
    tree.disconnect()
    session.disconnect()
    conn.disconnect()
    print("\n✓ Connection closed successfully")
    print("\n" + "=" * 60)
    if file_ops_success:
        print("All connectivity tests passed!")
        print("The SMB server is ready for replay operations.")
    else:
        print("Basic connectivity tests passed, but file operations had issues.")
        print("The SMB server may have limited functionality.")
    print("=" * 60)
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        sys.exit(1)
