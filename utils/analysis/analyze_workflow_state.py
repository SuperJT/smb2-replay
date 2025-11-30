#!/usr/bin/env python3
"""
Analyze Workflow State

This script analyzes the workflow to understand what files should exist
vs what should be created during replay, based on the original capture.
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


def analyze_workflow_state(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze the workflow state to understand file operations."""
    
    # Track file states throughout the workflow
    file_states: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {
        'created': False,
        'opened': False,
        'first_seen': None,
        'last_seen': None,
        'operations': [],
        'create_operations': [],
        'open_operations': []
    })
    
    # Track directory states
    dir_states: defaultdict[str, dict[str, Any]] = defaultdict(lambda: {
        'created': False,
        'accessed': False,
        'first_seen': None,
        'last_seen': None,
        'operations': []
    })
    
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
        
        # Determine if this is a file or directory
        is_directory = False
        if cmd == '5':  # Create
            create_action = frame.get('smb2.create.action', '')
            if 'DIRECTORY' in str(create_action):
                is_directory = True
        
        if is_directory:
            # Track directory operations
            dir_states[filename]['operations'].append({
                'frame': frame_num,
                'command': cmd,
                'is_response': is_response,
                'create_action': frame.get('smb2.create.action', 'N/A'),
                'nt_status': frame.get('smb2.nt_status', 'N/A')
            })
            
            if dir_states[filename]['first_seen'] is None:
                dir_states[filename]['first_seen'] = frame_num
            dir_states[filename]['last_seen'] = frame_num
            
            if is_response and cmd == '5':
                create_action = frame.get('smb2.create.action', '')
                if create_action == 'DIRECTORY_CREATED':
                    dir_states[filename]['created'] = True
                    dir_states[filename]['create_operations'].append(frame_num)
                elif create_action == 'DIRECTORY_OPENED':
                    dir_states[filename]['accessed'] = True
                    dir_states[filename]['open_operations'].append(frame_num)
        else:
            # Track file operations
            file_states[filename]['operations'].append({
                'frame': frame_num,
                'command': cmd,
                'is_response': is_response,
                'create_action': frame.get('smb2.create.action', 'N/A'),
                'nt_status': frame.get('smb2.nt_status', 'N/A')
            })
            
            if file_states[filename]['first_seen'] is None:
                file_states[filename]['first_seen'] = frame_num
            file_states[filename]['last_seen'] = frame_num
            
            if is_response and cmd == '5':
                create_action = frame.get('smb2.create.action', '')
                if create_action == 'FILE_CREATED':
                    file_states[filename]['created'] = True
                    file_states[filename]['create_operations'].append(frame_num)
                elif create_action == 'FILE_OPENED':
                    file_states[filename]['opened'] = True
                    file_states[filename]['open_operations'].append(frame_num)
    
    return {
        'files': dict(file_states),
        'directories': dict(dir_states)
    }


def analyze_expected_responses(df: pd.DataFrame) -> Dict[str, Any]:
    """Analyze expected responses based on file state."""
    
    workflow_state = analyze_workflow_state(df)
    
    # Build file existence map at each point in time
    file_exists_at_frame = {}
    current_files = set()
    current_dirs = set()
    
    # Process frames chronologically to build state
    for idx, frame in df.iterrows():
        frame_num = frame.get('frame.number', idx)
        cmd = frame.get('smb2.cmd', 'N/A')
        filename = frame.get('smb2.filename', 'N/A')
        is_response = frame.get('smb2.flags.response', 'False') == 'True'
        
        if filename in ['N/A', '', '.', '..']:
            continue
            
        filename = filename.replace('/', '\\')
        
        if is_response and cmd == '5':  # Create response
            create_action = frame.get('smb2.create.action', '')
            nt_status = frame.get('smb2.nt_status', 'N/A')
            
            if create_action == 'FILE_CREATED' and nt_status == '0x00000000':
                current_files.add(filename)
            elif create_action == 'DIRECTORY_CREATED' and nt_status == '0x00000000':
                current_dirs.add(filename)
        
        # Record state at this frame
        file_exists_at_frame[frame_num] = {
            'files': current_files.copy(),
            'directories': current_dirs.copy()
        }
    
    return {
        'workflow_state': workflow_state,
        'file_exists_at_frame': file_exists_at_frame
    }


def predict_expected_responses(df: pd.DataFrame) -> Dict[str, Any]:
    """Predict expected responses based on workflow analysis."""
    
    analysis = analyze_expected_responses(df)
    workflow_state = analysis['workflow_state']
    file_exists_at_frame = analysis['file_exists_at_frame']
    
    predictions = []
    
    for idx, frame in df.iterrows():
        frame_num = frame.get('frame.number', idx)
        cmd = frame.get('smb2.cmd', 'N/A')
        filename = frame.get('smb2.filename', 'N/A')
        is_response = frame.get('smb2.flags.response', 'False') == 'True'
        
        if filename in ['N/A', '', '.', '..']:
            continue
            
        filename = filename.replace('/', '\\')
        
        if not is_response and cmd == '5':  # Create request
            # Check if file/directory should exist at this point
            prev_frame = frame_num - 1
            while prev_frame > 0 and prev_frame not in file_exists_at_frame:
                prev_frame -= 1
            
            if prev_frame in file_exists_at_frame:
                state = file_exists_at_frame[prev_frame]
                file_exists = filename in state['files']
                dir_exists = filename in state['directories']
                
                # Predict expected response
                if file_exists or dir_exists:
                    expected_status = '0x00000000'  # Success - file exists
                    expected_action = 'FILE_OPENED' if not dir_exists else 'DIRECTORY_OPENED'
                else:
                    expected_status = '0x00000000'  # Success - will be created
                    expected_action = 'FILE_CREATED' if not filename.endswith('\\') else 'DIRECTORY_CREATED'
                
                predictions.append({
                    'frame': frame_num,
                    'filename': filename,
                    'expected_status': expected_status,
                    'expected_action': expected_action,
                    'file_should_exist': file_exists,
                    'dir_should_exist': dir_exists
                })
    
    return {
        'predictions': predictions,
        'workflow_state': workflow_state
    }


def main():
    """Main analysis function."""
    if len(sys.argv) != 2:
        print("Usage: python analyze_workflow_state.py <session_file>")
        print("Example: python analyze_workflow_state.py smb2_session_0x9dbc000000000006.parquet")
        sys.exit(1)
    
    session_file = sys.argv[1]
    
    print("Analyzing Workflow State")
    print("=" * 50)
    
    # Load session data
    print(f"Loading session: {session_file}")
    df = load_session_data(session_file)
    
    if df.empty:
        print("❌ Failed to load session data")
        sys.exit(1)
    
    # Analyze workflow state
    print("Analyzing workflow state...")
    analysis = predict_expected_responses(df)
    
    workflow_state = analysis['workflow_state']
    predictions = analysis['predictions']
    
    # Display file analysis
    print(f"\n📁 File Analysis:")
    print("=" * 30)
    
    files = workflow_state['files']
    for filename, state in sorted(files.items()):
        print(f"\n📄 {filename}")
        print(f"   Created: {state['created']}")
        print(f"   Opened: {state['opened']}")
        print(f"   First seen: Frame {state['first_seen']}")
        print(f"   Last seen: Frame {state['last_seen']}")
        print(f"   Create operations: {state['create_operations']}")
        print(f"   Open operations: {state['open_operations']}")
    
    # Display directory analysis
    print(f"\n📂 Directory Analysis:")
    print("=" * 30)
    
    directories = workflow_state['directories']
    for dirname, state in sorted(directories.items()):
        print(f"\n📁 {dirname}")
        print(f"   Created: {state['created']}")
        print(f"   Accessed: {state['accessed']}")
        print(f"   First seen: Frame {state['first_seen']}")
        print(f"   Last seen: Frame {state['last_seen']}")
        print(f"   Create operations: {state['create_operations']}")
        print(f"   Open operations: {state['open_operations']}")
    
    # Display predictions
    print(f"\n🔮 Response Predictions:")
    print("=" * 30)
    
    for pred in predictions[:10]:  # Show first 10
        print(f"\nFrame {pred['frame']}: {pred['filename']}")
        print(f"   Expected Status: {pred['expected_status']}")
        print(f"   Expected Action: {pred['expected_action']}")
        print(f"   File should exist: {pred['file_should_exist']}")
        print(f"   Dir should exist: {pred['dir_should_exist']}")
    
    if len(predictions) > 10:
        print(f"\n... and {len(predictions) - 10} more predictions")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"   Total files: {len(files)}")
    print(f"   Total directories: {len(directories)}")
    print(f"   Files created: {sum(1 for f in files.values() if f['created'])}")
    print(f"   Files opened: {sum(1 for f in files.values() if f['opened'])}")
    print(f"   Directories created: {sum(1 for d in directories.values() if d['created'])}")
    print(f"   Directories accessed: {sum(1 for d in directories.values() if d['accessed'])}")
    print(f"   Response predictions: {len(predictions)}")


if __name__ == "__main__":
    main() 