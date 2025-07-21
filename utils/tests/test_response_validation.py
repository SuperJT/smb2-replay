#!/usr/bin/env python3
"""
Test Response Validation

This script tests the response validation functionality to ensure that
server responses during replay match what was captured in the Parquet files.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from smbreplay.replay import get_replayer
from smbreplay.session_manager import get_session_manager
from smbreplay.config import get_config

def test_response_validation():
    """Test response validation with real PCAP data."""
    print("Testing Response Validation")
    print("=" * 50)
    
    try:
        # Get session manager and load operations
        sm = get_session_manager()
        config = get_config()
        
        # Load capture path
        capture_path = sm.load_capture_path()
        if not capture_path:
            print("❌ No capture path configured")
            return False
        
        print(f"📁 Capture path: {capture_path}")
        
        # Get output directory
        output_dir = sm.get_output_directory(capture_path)
        if not output_dir:
            print("❌ No output directory found")
            return False
        
        print(f"📁 Output directory: {output_dir}")
        
        # List session files
        session_files = sm.list_session_files(output_dir)
        if not session_files:
            print("❌ No session files found")
            return False
        
        print(f"📄 Found {len(session_files)} session files")
        
        # Load second session (which has Create operations)
        session_file = session_files[1]  # Use second session
        print(f"📄 Loading session: {session_file}")
        
        session_frames, field_options, file_options, selected_fields = sm.load_and_summarize_session(capture_path, session_file)
        if session_frames is None:
            print("❌ Failed to load session")
            return False
        
        print(f"📊 Loaded {len(session_frames)} frames")
        
        # Get operations for replay
        operations = sm.update_operations(capture_path, session_file)
        if not operations:
            print("❌ No operations found")
            return False
        
        print(f"🔄 Found {len(operations)} operations for replay")
        
        # Filter to supported operations for testing (Tree Connect, Create, etc.)
        supported_operations = [op for op in operations if op.get('smb2.cmd') in ['3', '5'] and op.get('smb2.flags.response') == 'False']
        print(f"📝 Found {len(supported_operations)} supported operations")
        
        if not supported_operations:
            print("❌ No supported operations found")
            print("Available operations:")
            for op in operations[:10]:
                cmd = op.get('smb2.cmd', 'N/A')
                cmd_name = op.get('Command', 'Unknown')
                is_response = op.get('smb2.flags.response', 'False')
                print(f"  {cmd_name} (cmd={cmd}, response={is_response})")
            return False
        
        # Take first few operations for testing
        test_operations = supported_operations[:3]
        print(f"🧪 Testing with {len(test_operations)} operations:")
        for op in test_operations:
            print(f"  - {op.get('Command', 'Unknown')} (cmd={op.get('smb2.cmd', 'N/A')})")
        
        # Get replayer and enable response validation
        replayer = get_replayer()
        replayer.enable_response_validation(True)
        
        print("\n🔄 Starting replay with response validation...")
        
        # Run replay
        results = replayer.replay_session(test_operations)
        
        print("\n📊 Replay Results:")
        print(f"  Success: {results['success']}")
        print(f"  Total operations: {results['total_operations']}")
        print(f"  Successful operations: {results['successful_operations']}")
        print(f"  Failed operations: {results['failed_operations']}")
        
        # Show response validation results
        validation = results.get('response_validation', {})
        if validation:
            print(f"\n🔍 Response Validation Results:")
            print(f"  Enabled: {validation['enabled']}")
            print(f"  Total operations: {validation['total_operations']}")
            print(f"  Matching responses: {validation['matching_responses']}")
            print(f"  Mismatched responses: {validation['mismatched_responses']}")
            print(f"  Match rate: {validation['match_rate']:.1f}%")
            
            # Show details for mismatched responses
            if validation['mismatched_responses'] > 0:
                print(f"\n❌ Mismatched Responses:")
                for detail in validation['details']:
                    if not detail['status_match']:
                        print(f"  Frame {detail['frame']}: {detail['command']} ({detail['filename']})")
                        print(f"    Expected: {detail['expected_status']}")
                        print(f"    Actual: {detail['actual_status']}")
                        if detail['actual_error']:
                            print(f"    Error: {detail['actual_error']}")
        
        return results['success']
        
    except Exception as e:
        print(f"❌ Error during response validation test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main function."""
    success = test_response_validation()
    
    if success:
        print("\n✅ Response validation test completed successfully")
    else:
        print("\n❌ Response validation test failed")
        sys.exit(1)

if __name__ == "__main__":
    main() 