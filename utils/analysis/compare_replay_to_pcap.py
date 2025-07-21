#!/usr/bin/env python3
"""
Compare Replay to PCAP

This script compares replay results to the original PCAP file using tshark
commands to analyze the differences between original and replayed SMB operations.
"""

import sys
import os
import subprocess
import json
import tempfile
from typing import List, Dict, Any, Optional
from datetime import datetime

# Add the package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'smbreplay_package'))

from smbreplay.session_manager import get_session_manager
from smbreplay.config import get_config, get_logger
from smbreplay.replay import get_replayer

logger = get_logger()


def check_tshark_availability() -> bool:
    """Check if tshark is available."""
    try:
        result = subprocess.run(['tshark', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_pcap_path() -> Optional[str]:
    """Get the PCAP file path from configuration."""
    config = get_config()
    capture_path = config.get_capture_path()
    
    if not capture_path or not os.path.exists(capture_path):
        logger.error("No valid PCAP file found in configuration")
        return None
    
    return capture_path


def run_tshark_command(pcap_path: str, display_filter: str, fields: List[str]) -> List[Dict[str, Any]]:
    """Run tshark command and parse results."""
    
    # Build tshark command with tab-separated output for easier parsing
    cmd = [
        'tshark',
        '-r', pcap_path,
        '-T', 'fields',
        '-Y', display_filter
    ]
    
    # Add field specifications
    for field in fields:
        cmd.extend(['-e', field])
    
    try:
        logger.debug(f"Running tshark command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            logger.error(f"Tshark command failed: {result.stderr}")
            return []
        
        # Parse tab-separated output
        lines = result.stdout.strip().split('\n')
        operations = []
        
        for line in lines:
            if not line.strip():
                continue
                
            values = line.split('\t')
            
            # Create operation dict with all fields, filling missing ones with 'N/A'
            operation = {}
            for i, field in enumerate(fields):
                operation[field] = values[i] if i < len(values) else 'N/A'
            
            operations.append(operation)
        
        return operations
        
    except subprocess.TimeoutExpired:
        logger.error("Tshark command timed out")
        return []
    except Exception as e:
        logger.error(f"Error running tshark command: {e}")
        return []


def extract_smb_operations_from_pcap(pcap_path: str, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Extract SMB operations from PCAP file."""
    
    # Build display filter for SMB2 operations
    display_filter = "smb2"
    if session_id:
        display_filter += f" && smb2.sesid == {session_id}"
    
    # Fields to extract (only valid tshark SMB2 fields)
    fields = [
        'frame.number',
        'smb2.cmd',
        'smb2.msg_id',
        'smb2.sesid',
        'smb2.tid',
        'smb2.fid',
        'smb2.filename',
        'smb2.nt_status',
        'smb2.flags.response',
        'smb2.create.action'
    ]
    
    logger.info(f"Extracting SMB operations from PCAP: {pcap_path}")
    logger.info(f"Display filter: {display_filter}")
    
    results = run_tshark_command(pcap_path, display_filter, fields)
    
    # Process results - results are already in the correct format
    operations = results
    
    # Debug output
    print(f"   Raw tshark results: {len(results)} lines")
    if results:
        print(f"   First result: {results[0]}")
        print(f"   Fields requested: {fields}")
        print(f"   Fields in first result: {list(results[0].keys())}")
    
    logger.info(f"Extracted {len(operations)} SMB operations from PCAP")
    return operations


def compare_operations(original_ops: List[Dict[str, Any]], replayed_ops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare original and replayed operations."""
    
    # Group operations by message ID for comparison
    original_by_msg_id = {}
    for op in original_ops:
        msg_id = op.get('smb2.msg_id', 'N/A')
        if msg_id != 'N/A':
            # Handle comma-separated message IDs (request/response pairs)
            if ',' in msg_id:
                # Take the first message ID from the pair
                msg_id = msg_id.split(',')[0]
            original_by_msg_id[msg_id] = op
    
    replayed_by_msg_id = {}
    for op in replayed_ops:
        msg_id = op.get('smb2.msg_id', 'N/A')
        if msg_id and msg_id != 'N/A':
            replayed_by_msg_id[msg_id] = op
    
    # Focus comparison on operations that are in the replayed set
    # This gives us a more meaningful comparison for session-filtered operations
    print(f"   Original operations with message IDs: {len(original_by_msg_id)}")
    print(f"   Replayed operations with message IDs: {len(replayed_by_msg_id)}")
    
    # Get the message IDs that are in the session file
    session_msg_ids = set(replayed_by_msg_id.keys())
    print(f"   Session file message IDs: {len(session_msg_ids)}")
    
    # Filter original operations to only those in the session
    original_in_session = {msg_id: op for msg_id, op in original_by_msg_id.items() if msg_id in session_msg_ids}
    print(f"   Original operations matching session: {len(original_in_session)}")
    
    # Show some examples of matching message IDs
    matching_ids = set(original_by_msg_id.keys()) & session_msg_ids
    if matching_ids:
        print(f"   Example matching message IDs: {list(matching_ids)[:5]}")
    else:
        print(f"   No matching message IDs found")
        print(f"   Debug - Original message ID examples: {list(original_by_msg_id.keys())[:5]}")
        print(f"   Debug - Session message ID examples: {list(session_msg_ids)[:5]}")
    
    # Compare operations
    matches = []
    mismatches = []
    missing_in_replay: list[dict[str, Any]] = []
    extra_in_replay = []
    
    # Check for matches and mismatches (only for operations in the session)
    for msg_id in session_msg_ids:
        if msg_id in original_in_session and msg_id in replayed_by_msg_id:
            orig_op = original_in_session[msg_id]
            replay_op = replayed_by_msg_id[msg_id]
            
            # Compare key fields
            fields_to_compare = [
                'smb2.cmd', 'smb2.filename', 'smb2.create_disposition',
                'smb2.create_options', 'smb2.file_attributes',
                'smb2.desired_access', 'smb2.share_access', 'smb2.impersonation_level'
            ]
            
            differences = {}
            for field in fields_to_compare:
                orig_val = orig_op.get(field, 'N/A')
                replay_val = replay_op.get(field, 'N/A')
                if orig_val != replay_val:
                    differences[field] = {
                        'original': orig_val,
                        'replayed': replay_val
                    }
            
            if differences:
                mismatches.append({
                    'msg_id': msg_id,
                    'frame_number': orig_op.get('frame_number', 'N/A'),
                    'differences': differences,
                    'original': orig_op,
                    'replayed': replay_op
                })
            else:
                matches.append({
                    'msg_id': msg_id,
                    'frame_number': orig_op.get('frame_number', 'N/A'),
                    'operation': orig_op
                })
        else:
            # This shouldn't happen since we're only checking session message IDs
            pass
    
    # Check for extra operations in replay
    for msg_id in replayed_by_msg_id:
        if msg_id not in original_by_msg_id:
            extra_in_replay.append(replayed_by_msg_id[msg_id])
    
    # Calculate match rate based on session operations
    match_rate = len(matches) / len(session_msg_ids) * 100 if session_msg_ids else 0
    
    return {
        'matches': matches,
        'mismatches': mismatches,
        'missing_in_replay': missing_in_replay,
        'extra_in_replay': extra_in_replay,
        'total_original': len(original_ops),
        'total_replayed': len(replayed_ops),
        'operations_in_session': len(session_msg_ids),
        'match_rate': match_rate
    }


def analyze_response_patterns(original_ops: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze response patterns in original PCAP."""
    
    # Group by message ID to pair requests with responses
    request_response_pairs: dict[str, dict[str, dict[str, Any] | None]] = {}
    
    for op in original_ops:
        msg_id = op.get('smb2.msg_id', 'N/A')
        if msg_id == 'N/A':
            continue
            
        if msg_id not in request_response_pairs:
            request_response_pairs[msg_id] = {'request': None, 'response': None}
        
        is_response = op.get('smb2.flags.response', 'False') == 'True'
        if is_response:
            request_response_pairs[msg_id]['response'] = op
        else:
            request_response_pairs[msg_id]['request'] = op
    
    # Analyze patterns
    create_operations: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    
    for msg_id, pair in request_response_pairs.items():
        request = pair['request']
        response = pair['response']
        if request is not None and response is not None:
            if request.get('smb2.cmd') == '5':  # Create operation
                create_operations.append({
                    'msg_id': msg_id,
                    'frame_number': request.get('frame_number', 'N/A'),
                    'filename': request.get('smb2.filename', 'N/A'),
                    'create_disposition': request.get('smb2.create_disposition', 'N/A'),
                    'create_options': request.get('smb2.create_options', 'N/A'),
                    'response_status': response.get('smb2.nt_status', 'N/A'),
                    'response_action': response.get('smb2.create.action', 'N/A')
                })
                status = response.get('smb2.nt_status', 'N/A')
                status_counts[status] = status_counts.get(status, 0) + 1
    
    return {
        'create_operations': create_operations,
        'status_counts': status_counts,
        'total_pairs': len([p for p in request_response_pairs.values() if p['request'] and p['response']])
    }


def main():
    """Main comparison function."""
    if len(sys.argv) != 2:
        print("Usage: python compare_replay_to_pcap.py <session_file>")
        print("Example: python compare_replay_to_pcap.py smb2_session_0x9dbc000000000006.parquet")
        sys.exit(1)
    
    session_file = sys.argv[1]
    
    print("Comparing Replay to Original PCAP")
    print("=" * 50)
    
    # Check tshark availability
    if not check_tshark_availability():
        print("❌ Tshark not available. Please install Wireshark/tshark.")
        sys.exit(1)
    
    print("✅ Tshark is available")
    
    # Get PCAP path
    pcap_path = get_pcap_path()
    if not pcap_path:
        print("❌ No PCAP file found in configuration")
        sys.exit(1)
    
    print(f"📁 PCAP file: {pcap_path}")
    
    # Extract session ID from session file name
    session_id = None
    if '0x' in session_file:
        session_id = session_file.split('0x')[1].split('.')[0]
        session_id = f"0x{session_id}"
    
    # Test the session ID format
    print(f"🔍 Testing session ID filter...")
    test_cmd = [
        'tshark', '-r', pcap_path, 
        '-Y', f'smb2 && smb2.sesid == {session_id}', 
        '-T', 'fields', '-e', 'frame.number', '-e', 'smb2.cmd'
    ]
    test_result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=10)
    print(f"   Test command: {' '.join(test_cmd)}")
    print(f"   Test result: {len(test_result.stdout.strip().split('\n'))} lines")
    
    if not test_result.stdout.strip():
        print(f"⚠️  No results with session ID filter, trying without session filter...")
        session_id = None
    
    print(f"🔍 Session ID: {session_id}")
    
    # Extract operations from PCAP
    print("\n📊 Extracting operations from PCAP...")
    original_ops = extract_smb_operations_from_pcap(pcap_path, session_id)
    
    if not original_ops:
        print("❌ No SMB operations found in PCAP")
        sys.exit(1)
    
    print(f"✅ Extracted {len(original_ops)} operations from PCAP")
    
    # Run replay to get replayed operations
    print("\n🔄 Running replay to get replayed operations...")
    replayer = get_replayer()
    
    # Get operations from session manager
    session_manager = get_session_manager()
    config = get_config()
    capture_path = config.get_capture_path()
    
    operations = session_manager.update_operations(capture_path, session_file)
    if not operations:
        print("❌ No operations found for replay")
        sys.exit(1)
    
    # Run replay
    results = replayer.replay_session(operations)
    
    if not results['success']:
        print(f"❌ Replay failed: {results.get('error', 'Unknown error')}")
        sys.exit(1)
    
    print(f"✅ Replay completed: {results['successful_operations']}/{results['total_operations']} operations")
    
    # Get validation results
    validation_results = replayer.get_response_validation_results()
    
    # Compare operations
    print("\n🔍 Comparing operations...")
    comparison = compare_operations(original_ops, operations)
    
    # Analyze original response patterns
    print("\n📈 Analyzing original response patterns...")
    patterns = analyze_response_patterns(original_ops)
    
    # Display results
    print(f"\n📊 Comparison Results:")
    print("=" * 30)
    print(f"   PCAP total SMB operations: {comparison['total_original']}")
    print(f"   Session file operations: {comparison['total_replayed']}")
    print(f"   Operations in session: {comparison['operations_in_session']}")
    print(f"   Exact matches: {len(comparison['matches'])}")
    print(f"   Mismatches: {len(comparison['mismatches'])}")
    print(f"   Missing in replay: {len(comparison['missing_in_replay'])}")
    print(f"   Extra in replay: {len(comparison['extra_in_replay'])}")
    print(f"   Session match rate: {comparison['match_rate']:.1f}%")
    
    # Display original response patterns
    print(f"\n📈 Session Response Patterns (from PCAP):")
    print("=" * 30)
    for status, count in sorted(patterns['status_counts'].items()):
        print(f"   {status}: {count} operations")
    
    # Display validation results
    if validation_results['enabled']:
        print(f"\n✅ Replay Validation Results:")
        print("=" * 30)
        print(f"   Total operations: {validation_results['total_operations']}")
        print(f"   Matching responses: {validation_results['matching_responses']}")
        print(f"   Mismatched responses: {validation_results['mismatched_responses']}")
        print(f"   Match rate: {validation_results['match_rate']:.1f}%")
    
    # Display detailed mismatches
    if comparison['mismatches']:
        print(f"\n❌ Detailed Mismatches (First 5):")
        print("=" * 40)
        
        for i, mismatch in enumerate(comparison['mismatches'][:5], 1):
            print(f"\n{i}. Frame {mismatch['frame_number']} (Msg ID: {mismatch['msg_id']})")
            print(f"   Filename: {mismatch['original'].get('smb2.filename', 'N/A')}")
            
            for field, diff in mismatch['differences'].items():
                print(f"   {field}:")
                print(f"     Original: {diff['original']}")
                print(f"     Replayed: {diff['replayed']}")
    
    # Summary
    print(f"\n🎯 Summary:")
    print("=" * 20)
    print(f"📁 Session file contains {comparison['total_replayed']} operations from {comparison['total_original']} total PCAP operations")
    print(f"🎯 This represents the filtered SMB session for replay analysis")
    
    if comparison['match_rate'] > 90:
        print("✅ Excellent session match rate - replay is very faithful to original session")
    elif comparison['match_rate'] > 70:
        print("⚠️  Good session match rate - some differences but mostly accurate")
    else:
        print("❌ Low session match rate - significant differences from original session")
    
    if validation_results['enabled'] and validation_results['match_rate'] > 70:
        print("✅ Response validation shows good agreement with expected responses")
    elif validation_results['enabled']:
        print("⚠️  Response validation shows some differences from expected responses")


if __name__ == "__main__":
    main() 