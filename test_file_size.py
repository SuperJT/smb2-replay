#!/usr/bin/env python3
"""
Test script to verify file size setting via SMB.
Run on tracer server to test different approaches.
"""

import struct
import sys
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open
from smbprotocol.exceptions import SMBException

# Config - adjust as needed
SERVER_IP = "192.168.0.164"  # lab SMB server
SHARE = "share1"
DOMAIN = ""
USERNAME = "testuser"
PASSWORD = "testpass"
TEST_PATH = "test_size_file.txt"
TARGET_SIZE = 100000  # 100KB


def connect():
    """Establish SMB connection."""
    conn = Connection(uuid="test-uuid", server=SERVER_IP, port=445)
    conn.connect()
    
    session = Session(conn, USERNAME, PASSWORD, domain=DOMAIN)
    session.connect()
    
    tree = TreeConnect(session, f"\\\\{SERVER_IP}\\{SHARE}")
    tree.connect()
    
    return conn, session, tree


def test_setinfo_eof(tree, path, size):
    """Test SETINFO with FILE_END_OF_FILE_INFO (class 20)."""
    print(f"\n=== Testing SETINFO EOF (class 20) for {path}, size={size} ===")
    try:
        file_open = Open(tree, path)
        file_open.create(
            impersonation_level=0,
            desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            file_attributes=0,
            share_access=0x00000007,  # Full share
            create_disposition=2,  # CREATE_ALWAYS
            create_options=0,
        )
        print(f"  File created: {path}")
        
        # Try SETINFO EOF
        eof_buffer = struct.pack('<Q', size)  # 8-byte little-endian
        print(f"  Sending SETINFO: info_type=1, file_info_class=20, buffer={eof_buffer.hex()}")
        file_open.set_info(
            info_type=1,
            file_info_class=20,  # SMB2_FILE_END_OF_FILE_INFO
            additional_information=0,
            buffer=eof_buffer,
        )
        print(f"  ✅ SETINFO EOF succeeded!")
        
        file_open.close()
        return True
    except SMBException as e:
        print(f"  ❌ SETINFO EOF failed: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {type(e).__name__}: {e}")
        return False


def test_setinfo_allocation(tree, path, size):
    """Test SETINFO with FILE_ALLOCATION_INFO (class 19)."""
    print(f"\n=== Testing SETINFO Allocation (class 19) for {path}, size={size} ===")
    try:
        file_open = Open(tree, path)
        file_open.create(
            impersonation_level=0,
            desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            file_attributes=0,
            share_access=0x00000007,  # Full share
            create_disposition=2,  # CREATE_ALWAYS
            create_options=0,
        )
        print(f"  File created: {path}")
        
        # Try SETINFO Allocation
        alloc_buffer = struct.pack('<Q', size)  # 8-byte little-endian
        print(f"  Sending SETINFO: info_type=1, file_info_class=19, buffer={alloc_buffer.hex()}")
        file_open.set_info(
            info_type=1,
            file_info_class=19,  # SMB2_FILE_ALLOCATION_INFO
            additional_information=0,
            buffer=alloc_buffer,
        )
        print(f"  ✅ SETINFO Allocation succeeded!")
        
        file_open.close()
        return True
    except SMBException as e:
        print(f"  ❌ SETINFO Allocation failed: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {type(e).__name__}: {e}")
        return False


def test_write_extend(tree, path, size):
    """Test extending file via WRITE at offset."""
    print(f"\n=== Testing WRITE extend for {path}, size={size} ===")
    try:
        file_open = Open(tree, path)
        file_open.create(
            impersonation_level=0,
            desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            file_attributes=0,
            share_access=0x00000007,  # Full share
            create_disposition=2,  # CREATE_ALWAYS
            create_options=0,
        )
        print(f"  File created: {path}")
        
        # Write single byte at (size-1) to extend
        offset = size - 1
        print(f"  Writing 1 byte at offset {offset}")
        file_open.write(b'\x00', offset)
        print(f"  ✅ WRITE extend succeeded!")
        
        file_open.close()
        return True
    except SMBException as e:
        print(f"  ❌ WRITE extend failed: {e}")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {type(e).__name__}: {e}")
        return False


def main():
    print("=" * 60)
    print("SMB File Size Test")
    print("=" * 60)
    print(f"Server: {SERVER_IP}")
    print(f"Share: {SHARE}")
    print(f"Target size: {TARGET_SIZE} bytes")
    
    try:
        conn, session, tree = connect()
        print("✅ Connected to SMB server")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        sys.exit(1)
    
    # Test 1: SETINFO EOF
    test_setinfo_eof(tree, "test_setinfo_eof.txt", TARGET_SIZE)
    
    # Test 2: SETINFO Allocation
    test_setinfo_allocation(tree, "test_setinfo_alloc.txt", TARGET_SIZE)
    
    # Test 3: WRITE extend
    test_write_extend(tree, "test_write_extend.txt", TARGET_SIZE)
    
    print("\n" + "=" * 60)
    print("Tests complete. Check file sizes on SMB server.")
    print("=" * 60)
    
    tree.disconnect()
    session.disconnect()
    conn.disconnect()


if __name__ == "__main__":
    main()
