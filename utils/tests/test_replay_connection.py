#!/usr/bin/env python3
"""
Test SMB Replay Connection

This script tests the SMB connection using the current replay configuration
to verify that the replay functionality can connect to the target server.
Moved to utils/ for better organization.
"""

import sys
import os
import uuid
import logging
from typing import Dict, Any, Optional

# Add the package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'smbreplay_package'))

from smbreplay.config import get_config
from smbreplay.replay import SMB2Replayer

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def test_replay_connection():
    """Test the replay connection using current configuration."""
    print("Testing SMB Replay Connection")
    print("=" * 50)
    
    # Get configuration and force reload
    config = get_config()
    config._load_config()  # Force reload from disk
    replay_config = config.replay_config
    
    print(f"Server IP: {replay_config.get('server_ip', 'Not configured')}")
    print(f"Domain: {replay_config.get('domain', 'Not configured')}")
    print(f"Username: {replay_config.get('username', 'Not configured')}")
    print(f"Tree Name: {replay_config.get('tree_name', 'Not configured')}")
    print(f"Max Wait: {replay_config.get('max_wait', 5.0)} seconds")
    print()
    
    # Test connection step by step
    print("Step 1: Testing basic connection...")
    try:
        from smbprotocol.connection import Connection
        
        # Use configured server IP
        server_ip = replay_config.get("server_ip", "127.0.0.1")
        max_wait = replay_config.get("max_wait", 5.0)
        
        connection = Connection(uuid.uuid4(), server_ip, 445)
        connection.connect(timeout=max_wait)
        print(f"✓ Connected to {server_ip}:445")
        
        # Test session with user authentication
        print("Step 2: Testing session authentication...")
        from smbprotocol.session import Session
        
        # Use configured credentials
        username = replay_config.get("username", "jtownsen")
        password = replay_config.get("password", "P@ssw0rd")
        
        session = Session(connection, username, password, require_encryption=False)
        session.connect()
        print(f"✓ User authentication successful for {username}")
        
        # Test tree connect
        print("Step 3: Testing tree connect...")
        from smbprotocol.tree import TreeConnect
        
        # Use configured tree name
        tree_name = replay_config.get("tree_name", "testshare")
        tree_path = f"\\\\{server_ip}\\{tree_name}"
        
        tree = TreeConnect(session, tree_path)
        tree.connect()
        print(f"✓ Connected to share: {tree_path}")
        
        # Test basic file operation
        print("Step 4: Testing file operation...")
        from smbprotocol.open import Open
        
        import time
        test_file = f"replay_test_{int(time.time())}.txt"
        file_open = Open(tree, test_file)
        # Create with standard parameters for file creation
        file_open.create(
            impersonation_level=0,  # SECURITY_ANONYMOUS
            desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
            file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
            share_access=0x00000001,  # FILE_SHARE_READ
            create_disposition=2,  # FILE_CREATE
            create_options=0  # No special options
        )
        
        test_data = b"SMB Replay connection test successful!"
        bytes_written = file_open.write(test_data, 0)
        print(f"✓ Wrote {bytes_written} bytes to {test_file}")
        
        read_data = file_open.read(0, len(test_data))
        print(f"✓ Read {len(read_data)} bytes from {test_file}")
        
        file_open.close()
        print("✓ File operation completed successfully")
        
        # Clean up
        tree.disconnect()
        session.disconnect()
        connection.disconnect()
        
        # Update configuration with working settings
        print(f"\nUpdating configuration with working settings...")
        config.update_replay_config(
            server_ip=server_ip,
            username=username,
            password=password,
            tree_name=tree_name,
            domain=""
        )
        config.save_config()
        print("✓ Configuration updated!")
        
        print("\n🎉 All tests passed! SMB replay connection is working.")
        
    except Exception as e:
        print(f"\n❌ Connection test failed: {e}")
        logger.error(f"Connection test failed: {e}", exc_info=True)
        raise


def test_replay_configuration():
    """Test the replay configuration and show current settings."""
    print("Current Replay Configuration")
    print("=" * 50)
    
    config = get_config()
    config._load_config()  # Force reload from disk
    replay_config = config.replay_config
    
    for key, value in replay_config.items():
        if key == 'password':
            display_value = '***' if value and value != 'PASSWORD' else value
        else:
            display_value = value
        print(f"{key}: {display_value}")
    
    print()
    
    # Check if required fields are set
    required_fields = ['server_ip', 'username', 'tree_name']
    missing_fields = []
    
    for field in required_fields:
        if not replay_config.get(field):
            missing_fields.append(field)
    
    if missing_fields:
        print(f"⚠️  Missing required configuration: {', '.join(missing_fields)}")
        print("Use 'smbreplay config set <field> <value>' to configure")
        raise ValueError(f"Missing required configuration: {', '.join(missing_fields)}")
    else:
        print("✓ All required fields are configured")


def test_replay_system():
    """Test the actual replay system with operations that test different create dispositions."""
    print("\nTesting Replay System")
    print("=" * 30)
    
    try:
        from smbreplay.replay import SMB2Replayer
        
        # Create test operations with different create dispositions
        test_operations = [
            # First operation: Create a new file (FILE_CREATE)
            {
                'smb2.cmd': '5',  # Create
                'smb2.filename': 'replay_create_test.txt',
                'smb2.flags.response': 'False',
                'smb2.impersonation_level': '0',  # SECURITY_ANONYMOUS
                'smb2.desired_access': '0x80000000',  # GENERIC_READ
                'smb2.file_attributes': '0',  # FILE_ATTRIBUTE_NORMAL
                'smb2.share_access': '0x00000001',  # FILE_SHARE_READ
                'smb2.create_disposition': '2',  # FILE_CREATE
                'smb2.create_options': '0',  # No special options
                'Frame': '1',
                'Command': 'Create'
            },
            # Second operation: Open an existing file (FILE_OPEN)
            {
                'smb2.cmd': '5',  # Create
                'smb2.filename': 'replay_system_test.txt',
                'smb2.flags.response': 'False',
                'smb2.impersonation_level': '0',  # SECURITY_ANONYMOUS
                'smb2.desired_access': '0x80000000',  # GENERIC_READ
                'smb2.file_attributes': '0',  # FILE_ATTRIBUTE_NORMAL
                'smb2.share_access': '0x00000001',  # FILE_SHARE_READ
                'smb2.create_disposition': '1',  # FILE_OPEN
                'smb2.create_options': '0',  # No special options
                'Frame': '2',
                'Command': 'Create'
            }
        ]
        
        replayer = SMB2Replayer()
        
        def status_callback(msg):
            print(f"  {msg}")
        
        print("Running replay system test with different create dispositions...")
        result = replayer.replay_session(test_operations, status_callback)
        
        if result.get('success'):
            print(f"\n✅ Replay system test successful!")
            print(f"   Operations: {result.get('successful_operations', 0)}/{result.get('total_operations', 0)}")
        else:
            print(f"\n❌ Replay system test failed: {result.get('error', 'Unknown error')}")
            raise AssertionError(f"Replay system test failed: {result.get('error', 'Unknown error')}")
        
    except Exception as e:
        print(f"❌ Replay system test failed: {e}")
        raise


def main():
    """Main test function."""
    print("SMB Replay Connection Test")
    print("=" * 50)
    
    # Test configuration first
    config_ok = test_replay_configuration()
    
    if config_ok:
        # Test connection
        connection_ok = test_replay_connection()
        
        if connection_ok:
            print("\n✅ SMB replay connection is working!")
            
            # Test the actual replay system
            replay_ok = test_replay_system()
            
            if replay_ok:
                print("\n🎉 SMB replay system is fully functional!")
                print("\nTo use with real data:")
                print("1. Configure a case: smbreplay config set case_id <case_id>")
                print("2. Ingest a PCAP: smbreplay ingest --case <case_id> --trace <file.pcap>")
                print("3. List sessions: smbreplay list sessions --case <case_id>")
                print("4. Replay a session: smbreplay replay <session_id> --case <case_id>")
            else:
                print("\n⚠ Connection works but replay system needs adjustment.")
        else:
            print("\n❌ SMB replay connection failed. Check configuration and network.")
    else:
        print("\n❌ Configuration is incomplete. Please configure required fields.")
    
    print("\nTest completed!")


if __name__ == "__main__":
    main() 