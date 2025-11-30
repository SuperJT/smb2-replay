#!/usr/bin/env python3
"""
Analyze Response Mismatches

This script analyzes response mismatches from replay operations and compares
the original requests with the replayed requests to identify differences.
"""

import sys
import os
import pandas as pd
import pyarrow.parquet as pq
from typing import List, Dict, Any, Optional

# Add the package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'smbreplay_package'))

from smbreplay.replay import get_replayer
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


def extract_request_response_pairs(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Extract request-response pairs from session data."""
    pairs = []
    
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
            pairs.append({
                'msg_id': msg_id,
                'frame_number': request.get('frame.number', 'N/A'),
                'command': request.get('smb2.cmd', 'N/A'),
                'command_name': request.get('smb2.cmd_desc', 'Unknown'),
                'filename': request.get('smb2.filename', 'N/A'),
                'request': request,
                'response': response,
                'expected_status': response.get('smb2.nt_status', 'N/A'),
                'expected_status_desc': response.get('smb2.nt_status_desc', 'N/A')
            })
    
    return pairs


def analyze_request_parameters(request: pd.Series) -> Dict[str, Any]:
    """Analyze request parameters for detailed comparison."""
    cmd = request.get('smb2.cmd', 'N/A')
    
    params = {
        'command': cmd,
        'filename': request.get('smb2.filename', 'N/A'),
        'msg_id': request.get('smb2.msg_id', 'N/A'),
        'session_id': request.get('smb2.sesid', 'N/A'),
        'tree_id': request.get('smb2.tid', 'N/A'),
        'file_id': request.get('smb2.fid', 'N/A'),
    }
    
    # Add command-specific parameters
    if cmd == '5':  # Create
        params.update({
            'impersonation_level': request.get('smb2.impersonation_level', 'N/A'),
            'desired_access': request.get('smb2.desired_access', 'N/A'),
            'file_attributes': request.get('smb2.file_attributes', 'N/A'),
            'share_access': request.get('smb2.share_access', 'N/A'),
            'create_disposition': request.get('smb2.create_disposition', 'N/A'),
            'create_options': request.get('smb2.create_options', 'N/A'),
            'create_action': request.get('smb2.create.action', 'N/A'),
        })
    elif cmd == '8':  # Read
        params.update({
            'read_offset': request.get('smb2.read.offset', 'N/A'),
            'read_length': request.get('smb2.read.length', 'N/A'),
        })
    elif cmd == '9':  # Write
        params.update({
            'write_offset': request.get('smb2.write.offset', 'N/A'),
            'write_length': request.get('smb2.write.length', 'N/A'),
        })
    elif cmd == '3':  # Tree Connect
        params.update({
            'tree_connect_path': request.get('smb2.tree', 'N/A'),
        })
    
    return params


def compare_requests(original_request: Dict[str, Any], replayed_request: Dict[str, Any]) -> Dict[str, Any]:
    """Compare original and replayed requests."""
    differences = {}
    
    # Compare all parameters
    for key in original_request.keys():
        if key in replayed_request:
            orig_val = original_request[key]
            replay_val = replayed_request[key]
            
            if orig_val != replay_val:
                differences[key] = {
                    'original': orig_val,
                    'replayed': replay_val,
                    'match': False
                }
        else:
            differences[key] = {
                'original': original_request[key],
                'replayed': 'MISSING',
                'match': False
            }
    
    # Check for extra parameters in replayed request
    for key in replayed_request.keys():
        if key not in original_request:
            differences[key] = {
                'original': 'MISSING',
                'replayed': replayed_request[key],
                'match': False
            }
    
    return differences


def main():
    """Main analysis function."""
    if len(sys.argv) != 2:
        print("Usage: python analyze_response_mismatches.py <session_file>")
        print("Example: python analyze_response_mismatches.py smb2_session_0x9dbc000000000006.parquet")
        sys.exit(1)
    
    session_file = sys.argv[1]
    
    print("Analyzing Response Mismatches")
    print("=" * 50)
    
    # Load session data
    print(f"Loading session: {session_file}")
    df = load_session_data(session_file)
    
    if df.empty:
        print("❌ Failed to load session data")
        sys.exit(1)
    
    # Extract request-response pairs
    print("Extracting request-response pairs...")
    pairs = extract_request_response_pairs(df)
    print(f"Found {len(pairs)} request-response pairs")
    
    # Run replay to get validation results
    print("Running replay to get validation results...")
    replayer = get_replayer()
    
    # Get operations from session manager
    session_manager = get_session_manager()
    config = get_config()
    capture_path = config.get_capture_path()
    
    operations = session_manager.update_operations(capture_path, session_file)
    if not operations:
        print("❌ No operations found for replay")
        sys.exit(1)
    
    print(f"Running replay with {len(operations)} operations...")
    
    # Run replay
    results = replayer.replay_session(operations)
    
    if not results['success']:
        print(f"❌ Replay failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)
    
    print(f"✅ Replay completed: {results['successful_operations']}/{results['total_operations']} operations")
    
    # Get replay validation results
    print("Getting replay validation results...")
    validation_results = replayer.get_response_validation_results()
    
    if not validation_results['enabled'] or not validation_results['details']:
        print("❌ No validation results available.")
        sys.exit(1)
    
    # Analyze mismatched responses
    mismatched_ops = [op for op in validation_results['details'] if not op['status_match']]
    
    if not mismatched_ops:
        print("✅ No response mismatches found!")
        return
    
    print(f"\n🔍 Found {len(mismatched_ops)} response mismatches:")
    print("=" * 50)
    
    for i, mismatch in enumerate(mismatched_ops, 1):
        frame = mismatch['frame']
        command = mismatch['command']
        filename = mismatch['filename']
        expected = mismatch['expected_status']
        actual = mismatch['actual_status']
        
        print(f"\n{i}. Frame {frame} - {command} ({filename})")
        print(f"   Expected: {expected}")
        print(f"   Actual:   {actual}")
        
        # Find the original request for this frame
        original_request = None
        for pair in pairs:
            if str(pair['frame_number']) == str(frame):
                original_request = pair['request']
                break
        
        if original_request is not None:
            # Analyze original request parameters
            orig_params = analyze_request_parameters(original_request)
            
            print(f"   📋 Original Request Parameters:")
            for key, value in orig_params.items():
                if value != 'N/A' and value is not None:
                    print(f"      {key}: {value}")
        else:
            print(f"   ⚠️  Could not find original request for frame {frame}")
    
    # Summary
    print(f"\n📊 Summary:")
    print(f"   Total operations: {validation_results['total_operations']}")
    print(f"   Matching responses: {validation_results['matching_responses']}")
    print(f"   Mismatched responses: {validation_results['mismatched_responses']}")
    print(f"   Match rate: {validation_results['match_rate']:.1f}%")
    
    # Common issues analysis
    print(f"\n🔍 Common Issues Analysis:")
    status_counts = {}
    for mismatch in mismatched_ops:
        expected = mismatch['expected_status']
        actual = mismatch['actual_status']
        key = f"{expected} -> {actual}"
        status_counts[key] = status_counts.get(key, 0) + 1
    
    for status_pair, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   {status_pair}: {count} operations")


if __name__ == "__main__":
    main() 