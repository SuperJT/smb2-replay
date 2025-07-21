#!/usr/bin/env python3
"""
Analyze Client Behavior

This script analyzes the actual client behavior to understand what operations
were attempted vs succeeded, and what the expected responses should be.
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


def analyze_client_behavior(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze the actual client behavior and responses."""
    
    # Track all create operations and their responses
    create_operations = []
    
    # Group by message ID to pair requests with responses
    for msg_id in df['smb2.msg_id'].unique():
        if pd.isna(msg_id) or msg_id == 'N/A':
            continue
            
        frames = df[df['smb2.msg_id'] == msg_id]
        if len(frames) != 2:  # Should have exactly 1 request and 1 response
            continue
            
        request = frames[frames['smb2.flags.response'] == 'False'].iloc[0] if len(frames[frames['smb2.flags.response'] == 'False']) > 0 else None
        response = frames[frames['smb2.flags.response'] == 'True'].iloc[0] if len(frames[frames['smb2.flags.response'] == 'True']) > 0 else None
        
        if request is not None and response is not None:
            cmd = request.get('smb2.cmd', 'N/A')
            if cmd == '5':  # Create operation
                create_operations.append({
                    'msg_id': msg_id,
                    'frame_number': request.get('frame.number', 'N/A'),
                    'filename': request.get('smb2.filename', 'N/A'),
                    'create_disposition': request.get('smb2.create_disposition', 'N/A'),
                    'create_options': request.get('smb2.create_options', 'N/A'),
                    'file_attributes': request.get('smb2.file_attributes', 'N/A'),
                    'desired_access': request.get('smb2.desired_access', 'N/A'),
                    'share_access': request.get('smb2.share_access', 'N/A'),
                    'impersonation_level': request.get('smb2.impersonation_level', 'N/A'),
                    'response_status': response.get('smb2.nt_status', 'N/A'),
                    'response_action': response.get('smb2.create.action', 'N/A'),
                    'response_status_desc': response.get('smb2.nt_status_desc', 'N/A')
                })
    
    # Analyze the patterns
    status_counts: defaultdict[str, int] = defaultdict(int)
    action_counts: defaultdict[str, int] = defaultdict(int)
    disposition_counts: defaultdict[str, int] = defaultdict(int)
    
    for op in create_operations:
        status_counts[op['response_status']] += 1
        action_counts[op['response_action']] += 1
        disposition_counts[op['create_disposition']] += 1
    
    # Categorize operations
    successful_creates = [op for op in create_operations if op['response_status'] == '0x00000000']
    failed_creates = [op for op in create_operations if op['response_status'] != '0x00000000']
    
    # Analyze what the client was trying to do
    client_intent = {}
    for op in create_operations:
        filename = op['filename']
        disposition = op['create_disposition']
        
        if filename not in client_intent:
            client_intent[filename] = {
                'operations': [],
                'first_disposition': disposition,
                'first_status': op['response_status'],
                'first_action': op['response_action']
            }
        
        client_intent[filename]['operations'].append(op)
    
    return {
        'create_operations': create_operations,
        'successful_creates': successful_creates,
        'failed_creates': failed_creates,
        'status_counts': dict(status_counts),
        'action_counts': dict(action_counts),
        'disposition_counts': dict(disposition_counts),
        'client_intent': client_intent
    }


def interpret_create_disposition(disposition: str) -> str:
    """Interpret create disposition value."""
    dispositions = {
        '1': 'FILE_SUPERSEDE',
        '2': 'FILE_OPEN',
        '3': 'FILE_CREATE',
        '4': 'FILE_OPEN_IF',
        '5': 'FILE_OVERWRITE',
        '6': 'FILE_OVERWRITE_IF'
    }
    return dispositions.get(str(disposition), f'Unknown({disposition})')


def interpret_create_options(options: str) -> str:
    """Interpret create options value."""
    try:
        options_int = int(options)
        options_list = []
        
        if options_int & 0x00000001:
            options_list.append('FILE_DIRECTORY_FILE')
        if options_int & 0x00000002:
            options_list.append('FILE_WRITE_THROUGH')
        if options_int & 0x00000004:
            options_list.append('FILE_SEQUENTIAL_ONLY')
        if options_int & 0x00000008:
            options_list.append('FILE_NO_INTERMEDIATE_BUFFERING')
        if options_int & 0x00000010:
            options_list.append('FILE_SYNCHRONOUS_IO_ALERT')
        if options_int & 0x00000020:
            options_list.append('FILE_SYNCHRONOUS_IO_NONALERT')
        if options_int & 0x00000040:
            options_list.append('FILE_NON_DIRECTORY_FILE')
        if options_int & 0x00000080:
            options_list.append('FILE_COMPLETE_IF_OPLOCKED')
        if options_int & 0x00000100:
            options_list.append('FILE_NO_EA_KNOWLEDGE')
        if options_int & 0x00000200:
            options_list.append('FILE_OPEN_FOR_RECOVERY')
        if options_int & 0x00000400:
            options_list.append('FILE_RANDOM_ACCESS')
        if options_int & 0x00000800:
            options_list.append('FILE_DELETE_ON_CLOSE')
        if options_int & 0x00001000:
            options_list.append('FILE_OPEN_BY_FILE_ID')
        if options_int & 0x00002000:
            options_list.append('FILE_OPEN_FOR_BACKUP_INTENT')
        if options_int & 0x00004000:
            options_list.append('FILE_NO_COMPRESSION')
        if options_int & 0x00008000:
            options_list.append('FILE_OPEN_REMOTE_INSTANCE')
        if options_int & 0x00010000:
            options_list.append('FILE_OPEN_REQUIRING_OPLOCK')
        if options_int & 0x00020000:
            options_list.append('FILE_DISALLOW_EXCLUSIVE')
        if options_int & 0x00040000:
            options_list.append('FILE_RESERVE_OPFILTER')
        if options_int & 0x00080000:
            options_list.append('FILE_OPEN_REPARSE_POINT')
        if options_int & 0x00100000:
            options_list.append('FILE_OPEN_NO_RECALL')
        if options_int & 0x00200000:
            options_list.append('FILE_OPEN_FOR_FREE_SPACE_QUERY')
        
        return ', '.join(options_list) if options_list else f'0x{options_int:08x}'
    except:
        return f'Unknown({options})'


def main():
    """Main analysis function."""
    if len(sys.argv) != 2:
        print("Usage: python analyze_client_behavior.py <session_file>")
        print("Example: python analyze_client_behavior.py smb2_session_0x9dbc000000000006.parquet")
        sys.exit(1)
    
    session_file = sys.argv[1]
    
    print("Analyzing Client Behavior")
    print("=" * 50)
    
    # Load session data
    print(f"Loading session: {session_file}")
    df = load_session_data(session_file)
    
    if df.empty:
        print("❌ Failed to load session data")
        sys.exit(1)
    
    # Analyze client behavior
    print("Analyzing client behavior...")
    analysis = analyze_client_behavior(df)
    
    # Display summary
    print(f"\n📊 Create Operations Summary:")
    print(f"   Total create operations: {len(analysis['create_operations'])}")
    print(f"   Successful creates: {len(analysis['successful_creates'])}")
    print(f"   Failed creates: {len(analysis['failed_creates'])}")
    
    # Display status distribution
    print(f"\n🔍 Response Status Distribution:")
    for status, count in sorted(analysis['status_counts'].items()):
        print(f"   {status}: {count} operations")
    
    # Display action distribution
    print(f"\n🔍 Create Action Distribution:")
    for action, count in sorted(analysis['action_counts'].items()):
        print(f"   {action}: {count} operations")
    
    # Display disposition distribution
    print(f"\n🔍 Create Disposition Distribution:")
    for disposition, count in sorted(analysis['disposition_counts'].items()):
        disp_name = interpret_create_disposition(disposition)
        print(f"   {disposition} ({disp_name}): {count} operations")
    
    # Display detailed analysis of first few operations
    print(f"\n📋 Detailed Analysis (First 10 operations):")
    print("=" * 50)
    
    for i, op in enumerate(analysis['create_operations'][:10], 1):
        print(f"\n{i}. Frame {op['frame_number']}: {op['filename']}")
        print(f"   Disposition: {op['create_disposition']} ({interpret_create_disposition(op['create_disposition'])})")
        print(f"   Options: {op['create_options']} ({interpret_create_options(op['create_options'])})")
        print(f"   File Attributes: {op['file_attributes']}")
        print(f"   Desired Access: {op['desired_access']}")
        print(f"   Share Access: {op['share_access']}")
        print(f"   Response Status: {op['response_status']} ({op['response_status_desc']})")
        print(f"   Response Action: {op['response_action']}")
    
    # Analyze client intent patterns
    print(f"\n🎯 Client Intent Analysis:")
    print("=" * 30)
    
    for filename, intent in list(analysis['client_intent'].items())[:10]:
        print(f"\n📄 {filename}")
        print(f"   First disposition: {intent['first_disposition']} ({interpret_create_disposition(intent['first_disposition'])})")
        print(f"   First status: {intent['first_status']}")
        print(f"   First action: {intent['first_action']}")
        print(f"   Total operations: {len(intent['operations'])}")
        
        # Analyze what the client was trying to do
        dispositions = [op['create_disposition'] for op in intent['operations']]
        if all(d == '3' for d in dispositions):
            print(f"   Intent: CREATE_NEW (client wanted to create new file)")
        elif all(d == '2' for d in dispositions):
            print(f"   Intent: OPEN_EXISTING (client wanted to open existing file)")
        elif all(d == '4' for d in dispositions):
            print(f"   Intent: OPEN_OR_CREATE (client wanted to open if exists, create if not)")
        else:
            print(f"   Intent: MIXED (client tried different approaches)")
    
    if len(analysis['client_intent']) > 10:
        print(f"\n... and {len(analysis['client_intent']) - 10} more files")


if __name__ == "__main__":
    main() 