#!/usr/bin/env python3
"""
Test SMB server connectivity and basic operations.
"""

import sys
import os
import socket
from typing import Optional

# Add the smbreplay package to the path
sys.path.append('/Users/jtownsen/bin/smb2-replay/smbreplay_package')

from smbreplay.config import get_config
from impacket.smbconnection import SMBConnection, SessionError


def test_basic_connectivity(server_ip: str, port: int = 445, timeout: int = 5) -> bool:
    """Test basic TCP connectivity to SMB port."""
    print(f"Testing basic connectivity to {server_ip}:{port}...")
    try:
        sock = socket.create_connection((server_ip, port), timeout=timeout)
        sock.close()
        print("✓ Port 445 is reachable")
        return True
    except Exception as e:
        print(f"✗ Port 445 connection failed: {e}")
        return False


def test_smb_login(server_ip: str, username: str, password: str, domain: str) -> Optional[SMBConnection]:
    """Test SMB login and return connection if successful."""
    print(f"Testing SMB login to {server_ip}...")
    try:
        conn = SMBConnection(server_ip, server_ip, sess_port=445)
        conn.login(username, password, domain)
        print("✓ SMB login successful")
        return conn
    except Exception as e:
        print(f"✗ SMB login failed: {e}")
        return None


def test_tree_connect(conn: SMBConnection, tree_name: str) -> Optional[int]:
    """Test tree connection and return TID if successful."""
    print(f"Testing tree connect to share '{tree_name}'...")
    try:
        tid = conn.connectTree(tree_name)
        print(f"✓ Tree connect successful, tid: {tid}")
        return tid
    except Exception as e:
        print(f"✗ Tree connect failed: {e}")
        return None


def test_directory_listing(conn: SMBConnection, tree_name: str, tid: int, path: str = '*') -> bool:
    """Test directory listing."""
    print(f"Testing directory listing for path '{path}'...")
    try:
        files = conn.listPath(tree_name, path)
        print(f"✓ Directory listing successful, found {len(files)} items")
        
        # Show first few items
        for i, file_info in enumerate(files[:5]):
            file_type = "DIR" if file_info.is_directory() else "FILE"
            print(f"  {file_type}: {file_info.get_longname()}")
        
        if len(files) > 5:
            print(f"  ... and {len(files) - 5} more items")
        
        return True
    except Exception as e:
        print(f"✗ Directory listing failed: {e}")
        return False


def test_file_operations(conn: SMBConnection, tid: int, tree_name: str, test_filename: str = 'smb2_replay_test.txt') -> bool:
    """Test basic file operations."""
    print(f"Testing file operations with '{test_filename}'...")
    
    try:
        # Try to create/open a test file
        print(f"  Creating file: {test_filename}")
        fid = conn.createFile(tid, test_filename, desiredAccess=0x80000000)  # GENERIC_READ
        print(f"  ✓ File create successful, fid: {fid}")
        
        # Close the file
        print(f"  Closing file: {test_filename}")
        conn.closeFile(tid, fid)
        print("  ✓ File close successful")
        
        # Try to delete the test file (uses tree_name, not tid!)
        delete_success = True
        try:
            print(f"  Deleting test file: {test_filename}")
            conn.deleteFile(tree_name, test_filename)
            print("  ✓ File delete successful")
        except Exception as e:
            print(f"  ✗ File delete failed: {e}")
            delete_success = False
        
        if not delete_success:
            print(f"  Warning: Test file '{test_filename}' may have been left behind")
        
        return delete_success
    except Exception as e:
        print(f"✗ File operations failed: {e}")
        return False


def main():
    """Main test function."""
    print("=" * 60)
    print("SMB2 Replay Server Connectivity Test")
    print("=" * 60)
    
    # Load configuration
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
    conn = test_smb_login(
        config.get_server_ip(),
        config.get_username(),
        config.get_password(),
        config.get_domain()
    )
    
    if not conn:
        print("\n✗ SMB login test failed. Check credentials and domain.")
        return False
    
    # Test 3: Tree connect
    tid = test_tree_connect(conn, config.get_tree_name())
    if not tid:
        print(f"\n✗ Tree connect test failed. Check if share '{config.get_tree_name()}' exists.")
        conn.close()
        return False
    
    # Test 4: Directory listing  
    if not test_directory_listing(conn, config.get_tree_name(), tid):
        print("\n✗ Directory listing test failed. Check share permissions.")
        conn.close()
        return False
    
    # Test 5: File operations
    file_ops_success = test_file_operations(conn, tid, config.get_tree_name())
    if not file_ops_success:
        print("\n✗ File operations test failed. Check write permissions.")
        conn.close()
        return False
    
    # Clean up
    conn.close()
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
