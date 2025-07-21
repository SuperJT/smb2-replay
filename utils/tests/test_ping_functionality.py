#!/usr/bin/env python3
"""
Test Ping Functionality

This script tests the ping functionality that differentiates between
pre-trace setup and actual replay operations.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from smbreplay.replay import get_replayer
from smbreplay.session_manager import get_session_manager
from smbreplay.config import get_config

def test_ping_functionality():
    """Test ping functionality for replay differentiation."""
    print("Testing Ping Functionality for Replay Differentiation")
    print("=" * 60)
    
    try:
        # Get replayer and configure ping
        replayer = get_replayer()
        
        # Test ping configuration
        print("\n🔧 Testing ping configuration...")
        replayer.set_ping_enabled(True)
        
        print("✅ Ping enabled - will ping replay server")
        
        # Test ping functionality
        print("\n🔄 Testing ping functionality...")
        replayer.send_replay_start_ping()
        
        # Test with specific server IP
        print("\n🔄 Testing ping with specific server IP...")
        replayer.send_replay_start_ping("127.0.0.1")
        
        # Test ping disable
        print("\n🔧 Testing ping disable...")
        replayer.set_ping_enabled(False)
        replayer.send_replay_start_ping()  # Should not ping
        
        # Re-enable for full test
        replayer.set_ping_enabled(True)
        
        # Get session manager and load operations for full test
        sm = get_session_manager()
        config = get_config()
        
        # Load capture path
        capture_path = sm.load_capture_path()
        if not capture_path:
            print("❌ No capture path configured")
            return False
        
        print(f"\n📁 Capture path: {capture_path}")
        
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
        
        # Load first session for testing
        session_file = session_files[0]
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
        
        # Filter to supported operations for testing
        supported_operations = [op for op in operations if op.get('smb2.cmd') in ['3', '5'] and op.get('smb2.flags.response') == 'False']
        print(f"📝 Found {len(supported_operations)} supported operations")
        
        if not supported_operations:
            print("❌ No supported operations found")
            return False
        
        # Take first few operations for testing
        test_operations = supported_operations[:2]
        print(f"🧪 Testing with {len(test_operations)} operations:")
        for op in test_operations:
            print(f"  - {op.get('Command', 'Unknown')} (cmd={op.get('smb2.cmd', 'N/A')})")
        
        # Configure replayer for test
        replayer.set_reset_mode('complete')
        replayer.enable_response_validation(True)
        replayer.set_ping_enabled(True)
        
        print(f"\n🚀 Starting replay with ping functionality...")
        print("   (Watch for ping output in logs)")
        
        # Run replay
        results = replayer.replay_session(test_operations)
        
        print(f"\n📊 Replay Results:")
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
        
        return results['success']
        
    except Exception as e:
        print(f"❌ Error during ping functionality test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main function."""
    success = test_ping_functionality()
    
    if success:
        print("\n✅ Ping functionality test completed successfully")
        print("\n💡 Key Points:")
        print("  - Ping is sent after pre-trace setup but before replay operations")
        print("  - This clearly differentiates between setup and actual replay")
        print("  - Ping targets the replay server (no additional config needed)")
        print("  - Ping can be enabled/disabled as needed")
    else:
        print("\n❌ Ping functionality test failed")
        sys.exit(1)

if __name__ == "__main__":
    main() 