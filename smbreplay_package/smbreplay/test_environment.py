#!/usr/bin/env python3
"""
Test script to verify the SMB2 Replay environment setup
"""
import sys
import os

def test_imports():
    """Test that all required packages can be imported"""
    print("Testing Python environment setup...")
    print(f"Python version: {sys.version}")
    print(f"Current directory: {os.getcwd()}")
    print()
    
    # Test core dependencies
    packages = [
        ('pandas', 'Data manipulation'),
        ('pyarrow', 'Parquet file support'),
        ('numpy', 'Numerical computing'),
        ('paramiko', 'SSH connections'),
        ('scapy', 'Network packet analysis'),
        ('psutil', 'System monitoring'),
        ('click', 'CLI interface'),
        ('dotenv', 'Environment configuration'),
    ]
    
    failed = []
    for package, description in packages:
        try:
            __import__(package)
            print(f"✓ {package:15} - {description}")
        except ImportError as e:
            print(f"✗ {package:15} - {description} (FAILED: {e})")
            failed.append(package)
    
    print()
    if failed:
        print(f"❌ {len(failed)} packages failed to import: {', '.join(failed)}")
        raise ImportError(f"Failed to import packages: {', '.join(failed)}")
    else:
        print("✅ All packages imported successfully!")

def test_package_structure():
    """Test that the package structure is correct"""
    print("Testing package structure...")
    
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    required_files = [
        '__init__.py',
        '__main__.py',
        'config.py',
        'constants.py',
        'tshark_processor.py',
        'ingestion.py',
        'session_manager.py',
        'replay.py',
        'main.py',
        'utils.py',
    ]
    
    missing = []
    for file in required_files:
        file_path = os.path.join(script_dir, file)
        if os.path.exists(file_path):
            print(f"✓ Found: {file}")
        else:
            print(f"✗ Missing: {file}")
            missing.append(file)
    
    print()
    if missing:
        print(f"❌ {len(missing)} files missing: {', '.join(missing)}")
        raise FileNotFoundError(f"Missing required files: {', '.join(missing)}")
    else:
        print("✅ Package structure is complete!")

def test_system_tools():
    """Test that required system tools are available"""
    print("Testing system tools...")
    
    import subprocess
    
    tools = [
        ('tshark', 'Wireshark command-line tool', ['--version']),
        ('pcapfix', 'PCAP file repair utility', ['--version']),  # pcapfix shows usage on --version
    ]
    
    missing = []
    for tool, description, args in tools:
        try:
            result = subprocess.run([tool] + args, 
                                  capture_output=True, text=True, timeout=5, check=False)
            # pcapfix returns non-zero on --version but still shows version info
            if result.returncode == 0 or (tool == 'pcapfix' and 'pcapfix' in result.stdout):
                print(f"✓ {tool:15} - {description}")
            else:
                print(f"✗ {tool:15} - {description} (not working)")
                missing.append(tool)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print(f"✗ {tool:15} - {description} (not found)")
            missing.append(tool)
    
    print()
    if missing:
        print(f"⚠️  {len(missing)} tools missing: {', '.join(missing)}")
        print("   Install with: sudo apt install tshark pcapfix")
        raise FileNotFoundError(f"Missing system tools: {', '.join(missing)}")
    else:
        print("✅ All system tools available!")

def main():
    print("=" * 60)
    print("SMB2 Replay Environment Test")
    print("=" * 60)
    
    try:
        test_imports()
        test_package_structure()
        test_system_tools()
        
        print()
        print("🎉 Environment setup successful!")
        print("You can now use the SMB2 Replay system:")
        print("  python -m smbreplay --help")
        print("  python -m smbreplay info")
    except Exception as e:
        print(f"❌ Environment setup incomplete: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 