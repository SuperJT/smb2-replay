#!/usr/bin/env python3
"""
Capture PCAP during Setup Command

This script captures PCAP traffic while running the setup command
to debug why files aren't being created properly.
"""

import sys
import os
import subprocess
import time
import argparse

def capture_setup_pcap(session_id, pcap_file=None):
    """Capture PCAP during setup command execution."""
    
    if pcap_file is None:
        pcap_file = f"setup_debug_{session_id}_{int(time.time())}.pcap"
    
    print(f"Starting PCAP capture to {pcap_file}...")
    print(f"Will run: smbreplay setup {session_id}")
    
    try:
        # Start tshark in background
        tshark_cmd = f"sudo tshark -i lo -w {pcap_file} -f 'port 445' -q"
        print(f"Running: {tshark_cmd}")
        
        tshark_process = subprocess.Popen(tshark_cmd.split(), 
                                        stdout=subprocess.DEVNULL, 
                                        stderr=subprocess.DEVNULL)
        
        # Wait a moment for tshark to start
        time.sleep(3)
        
        print("PCAP capture started. Running setup command...")
        
        # Run the setup command
        setup_cmd = f"smbreplay setup {session_id}"
        print(f"Running: {setup_cmd}")
        
        setup_process = subprocess.run(setup_cmd.split(), 
                                     capture_output=False, 
                                     text=True)
        
        # Wait a moment for any final packets
        time.sleep(2)
        
        # Stop PCAP capture
        print("Stopping PCAP capture...")
        tshark_process.terminate()
        tshark_process.wait()
        
        print(f"✅ Setup command completed with return code: {setup_process.returncode}")
        print(f"📁 PCAP file saved: {pcap_file}")
        print(f"💡 Analyze the PCAP to see what SMB operations were performed")
        print(f"💡 Use: tshark -r {pcap_file} -Y 'smb2' to filter SMB2 traffic")
        print(f"💡 Use: tshark -r {pcap_file} -Y 'smb2.cmd == 5' to see Create operations")
        
    except Exception as e:
        print(f"❌ Capture failed: {e}")
        # Stop PCAP capture on error
        try:
            tshark_process.terminate()
        except:
            pass

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Capture PCAP during setup command")
    parser.add_argument("session_id", help="Session ID to setup (e.g., 0x9dbc000000000006)")
    parser.add_argument("-o", "--output", help="Output PCAP file name")
    
    args = parser.parse_args()
    
    capture_setup_pcap(args.session_id, args.output)

if __name__ == "__main__":
    main() 