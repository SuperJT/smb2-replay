#!/usr/bin/env python3
"""
Setup Workflow State

This script sets up the correct file system state for replay based on
workflow analysis, creating files and directories that should exist
before replay begins.
"""

import sys
import os
import pandas as pd
import pyarrow.parquet as pq
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict

# Add the package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'smbreplay_package'))

from smbreplay.session_manager import get_session_manager
from smbreplay.config import get_config, get_logger
from smbreplay.replay import get_replayer

logger = get_logger()


def load_session_data(session_file: str) -> pd.DataFrame:
    """Load session data from Parquet file."""
    config = get_config()
    capture_path = config.get_capture_path()
    
    if not capture_path:
        logger.error("No capture path configured")
        return pd.DataFrame()
    
    session_manager = get_session_manager()
    output_dir = session_manager.get_output_directory(capture_path)
    if not output_dir:
        logger.error("Could not determine output directory")
        return pd.DataFrame()
    
    session_path = os.path.join(output_dir, session_file)
    if not os.path.exists(session_path):
        logger.error(f"Session file not found: {session_path}")
        return pd.DataFrame()
    
    try:
        df = pq.read_table(session_path).to_pandas()
        logger.info(f"Loaded session with {len(df)} frames")
        return df
    except Exception as e:
        logger.error(f"Error loading session: {e}")
        return pd.DataFrame()


def analyze_required_files(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze what files and directories need to exist for replay."""
    
    # Track files that should exist (were opened, not created)
    required_files = set()
    required_dirs = set()
    
    # Track files that were created (should not exist initially)
    created_files = set()
    created_dirs = set()
    
    # Process frames chronologically
    for idx, frame in df.iterrows():
        frame_num = frame.get('frame.number', idx)
        cmd = frame.get('smb2.cmd', 'N/A')
        filename = frame.get('smb2.filename', 'N/A')
        is_response = frame.get('smb2.flags.response', 'False') == 'True'
        
        if filename in ['N/A', '', '.', '..']:
            continue
            
        # Normalize path
        filename = filename.replace('/', '\\')
        
        if is_response and cmd == '5':  # Create response
            create_action = frame.get('smb2.create.action', '')
            nt_status = frame.get('smb2.nt_status', 'N/A')
            
            if nt_status == '0x00000000':  # Success
                if create_action == 'FILE_CREATED':
                    created_files.add(filename)
                elif create_action == 'FILE_OPENED':
                    required_files.add(filename)
                elif create_action == 'DIRECTORY_CREATED':
                    created_dirs.add(filename)
                elif create_action == 'DIRECTORY_OPENED':
                    required_dirs.add(filename)
    
    return {
        'required_files': required_files,
        'required_dirs': required_dirs,
        'created_files': created_files,
        'created_dirs': created_dirs
    }


def setup_file_system_state(analysis: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
    """Set up the file system state for replay."""
    
    replayer = get_replayer()
    config = get_config()
    replay_config = config.replay_config
    
    server_ip = replay_config.get("server_ip", "127.0.0.1")
    domain = replay_config.get("domain", "")
    username = replay_config.get("username", "jtownsen")
    password = replay_config.get("password", "P@ssw0rd")
    tree_name = replay_config.get("tree_name", "testshare")
    
    print(f"Setting up file system state for replay...")
    print(f"Server: {server_ip}")
    print(f"Share: {tree_name}")
    print(f"Dry run: {dry_run}")
    
    if dry_run:
        print("\n📋 Files that should exist (were opened):")
        for file_path in sorted(analysis['required_files']):
            print(f"  📄 {file_path}")
        
        print("\n📂 Directories that should exist (were accessed):")
        for dir_path in sorted(analysis['required_dirs']):
            print(f"  📁 {dir_path}")
        
        print("\n📄 Files that will be created during replay:")
        for file_path in sorted(analysis['created_files']):
            print(f"  ➕ {file_path}")
        
        print("\n📂 Directories that will be created during replay:")
        for dir_path in sorted(analysis['created_dirs']):
            print(f"  ➕ {dir_path}")
        
        return {
            'success': True,
            'dry_run': True,
            'required_files': len(analysis['required_files']),
            'required_dirs': len(analysis['required_dirs']),
            'created_files': len(analysis['created_files']),
            'created_dirs': len(analysis['created_dirs'])
        }
    
    try:
        # Import SMB connection components
        from smbprotocol.connection import Connection
        from smbprotocol.session import Session
        from smbprotocol.tree import TreeConnect
        from smbprotocol.open import Open
        from smbprotocol.exceptions import SMBException
        import uuid
        
        # Connect to SMB server
        print("Connecting to SMB server...")
        connection = Connection(uuid.uuid4(), server_ip, 445)
        connection.connect()
        session = Session(connection, username, password, require_encryption=False)
        session.connect()
        tree = TreeConnect(session, f"\\\\{server_ip}\\{tree_name}")
        tree.connect()
        
        print("✅ Connected to SMB server")
        
        # Create required directories first
        created_dirs = 0
        for dir_path in sorted(analysis['required_dirs']):
            try:
                print(f"Creating directory: {dir_path}")
                dir_open = Open(tree, dir_path)
                dir_open.create(
                    impersonation_level=0,
                    desired_access=0x80000000,  # GENERIC_READ
                    file_attributes=0x00000010,  # FILE_ATTRIBUTE_DIRECTORY
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=3,  # FILE_OPEN_IF
                    create_options=1  # FILE_DIRECTORY_FILE
                )
                dir_open.close()
                created_dirs += 1
                print(f"✅ Created directory: {dir_path}")
            except SMBException as e:
                if "STATUS_OBJECT_NAME_COLLISION" in str(e):
                    print(f"⚠️  Directory already exists: {dir_path}")
                else:
                    print(f"❌ Failed to create directory {dir_path}: {e}")
        
        # Create required files
        created_files = 0
        for file_path in sorted(analysis['required_files']):
            try:
                print(f"Creating file: {file_path}")
                file_open = Open(tree, file_path)
                file_open.create(
                    impersonation_level=0,
                    desired_access=0x80000000 | 0x40000000,  # GENERIC_READ | GENERIC_WRITE
                    file_attributes=0,  # FILE_ATTRIBUTE_NORMAL
                    share_access=0x00000001,  # FILE_SHARE_READ
                    create_disposition=3,  # FILE_OPEN_IF
                    create_options=0
                )
                file_open.close()
                created_files += 1
                print(f"✅ Created file: {file_path}")
            except SMBException as e:
                if "STATUS_OBJECT_NAME_COLLISION" in str(e):
                    print(f"⚠️  File already exists: {file_path}")
                else:
                    print(f"❌ Failed to create file {file_path}: {e}")
        
        # Clean up connection
        tree.disconnect()
        session.disconnect()
        connection.disconnect()
        
        print(f"\n✅ File system setup completed:")
        print(f"   Directories created: {created_dirs}")
        print(f"   Files created: {created_files}")
        
        return {
            'success': True,
            'dry_run': False,
            'created_dirs': created_dirs,
            'created_files': created_files,
            'required_files': len(analysis['required_files']),
            'required_dirs': len(analysis['required_dirs'])
        }
        
    except Exception as e:
        print(f"❌ Failed to set up file system state: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def main():
    """Main setup function."""
    if len(sys.argv) < 2:
        print("Usage: python setup_workflow_state.py <session_file> [--dry-run]")
        print("Example: python setup_workflow_state.py smb2_session_0x9dbc000000000006.parquet")
        sys.exit(1)
    
    session_file = sys.argv[1]
    dry_run = '--dry-run' in sys.argv
    
    print("Setting up Workflow State for Replay")
    print("=" * 50)
    
    # Load session data
    print(f"Loading session: {session_file}")
    df = load_session_data(session_file)
    
    if df.empty:
        print("❌ Failed to load session data")
        sys.exit(1)
    
    # Analyze required files
    print("Analyzing required files...")
    analysis = analyze_required_files(df)
    
    # Set up file system state
    result = setup_file_system_state(analysis, dry_run)
    
    if result['success']:
        print(f"\n✅ Setup completed successfully!")
        if not dry_run:
            print(f"   Files created: {result['created_files']}")
            print(f"   Directories created: {result['created_dirs']}")
        else:
            print(f"   Files that should exist: {result['required_files']}")
            print(f"   Directories that should exist: {result['required_dirs']}")
            print(f"   Files that will be created: {result['created_files']}")
            print(f"   Directories that will be created: {result['created_dirs']}")
    else:
        print(f"❌ Setup failed: {result.get('error', 'Unknown error')}")
        sys.exit(1)


if __name__ == "__main__":
    main() 