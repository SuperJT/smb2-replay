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
        ('jupyter', 'Interactive notebooks'),
        ('ipywidgets', 'Interactive widgets'),
        ('paramiko', 'SSH connections'),
        ('scapy', 'Network packet analysis'),
        ('psutil', 'System monitoring'),
        ('impacket', 'SMB protocol library'),
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
        return False
    else:
        print("✅ All packages imported successfully!")
        return True

def test_notebook_path():
    """Test that the notebook file exists"""
    notebook_path = "impacket.ipynb"
    if os.path.exists(notebook_path):
        print(f"✓ Found notebook: {notebook_path}")
        return True
    else:
        print(f"✗ Notebook not found: {notebook_path}")
        return False

def main():
    print("=" * 60)
    print("SMB2 Replay Environment Test")
    print("=" * 60)
    
    imports_ok = test_imports()
    notebook_ok = test_notebook_path()
    
    print()
    if imports_ok and notebook_ok:
        print("🎉 Environment setup successful!")
        print("You can now run:")
        print("  jupyter lab")
        print("  jupyter notebook")
    else:
        print("❌ Environment setup incomplete. Please check the errors above.")
        sys.exit(1)

if __name__ == "__main__":
    main() 