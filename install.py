#!/usr/bin/env python3
"""
SMB2 Replay Installation Helper

This script helps you choose the right installation type for your needs.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def print_banner():
    """Print installation banner."""
    print("🚀 SMB2 Replay System Installation")
    print("=" * 40)
    print()

def check_requirements():
    """Check if basic requirements are met."""
    print("🔍 Checking requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        return False
    
    # Check pip
    if shutil.which("pip") is None:
        print("❌ pip is not available")
        return False
    
    # Check virtual environment
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("⚠️  Not running in a virtual environment (recommended)")
    
    print("✅ Basic requirements met")
    return True

def get_installation_type():
    """Get user's installation preference."""
    print("\n📦 Choose installation type:")
    print("1. Basic Installation (Recommended for new users)")
    print("   - Core SMB2 replay functionality")
    print("   - Command-line interface")
    print("   - Session analysis and replay")
    print()
    print("2. Development Tools (For developers and advanced users)")
    print("   - Everything from basic installation")
    print("   - Testing utilities and connectivity tools")
    print("   - Advanced analysis and debugging tools")
    print()
    print("3. Full Development (For contributors)")
    print("   - Everything from development tools")
    print("   - Code quality tools (black, flake8, mypy)")
    print("   - Testing framework")
    print()
    
    while True:
        try:
            choice = input("Enter your choice (1-3): ").strip()
            if choice in ['1', '2', '3']:
                return choice
            else:
                print("Please enter 1, 2, or 3")
        except KeyboardInterrupt:
            print("\n\nInstallation cancelled")
            sys.exit(0)

def install_package(install_type):
    """Install the package based on type."""
    print(f"\n🔧 Installing SMB2 Replay ({install_type})...")
    
    if install_type == "1":
        cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
        description = "Basic installation"
    elif install_type == "2":
        cmd = [sys.executable, "-m", "pip", "install", "-e", ".", "[dev-tools]"]
        description = "Development tools installation"
    else:  # install_type == "3"
        cmd = [sys.executable, "-m", "pip", "install", "-e", ".", "[dev-full]"]
        description = "Full development installation"
    
    try:
        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def test_installation():
    """Test the installation."""
    print("\n🧪 Testing installation...")
    
    try:
        # Test basic functionality
        result = subprocess.run([sys.executable, "-c", "import smbreplay; print('✅ smbreplay package imported successfully')"], 
                              check=True, capture_output=True, text=True)
        print(result.stdout.strip())
        
        # Test CLI
        result = subprocess.run([sys.executable, "-m", "smbreplay", "--help"], 
                              check=True, capture_output=True, text=True)
        print("✅ CLI interface working")
        
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation test failed: {e}")
        return False

def show_next_steps(install_type):
    """Show next steps based on installation type."""
    print("\n🎉 Installation completed successfully!")
    print("\n📋 Next steps:")
    
    if install_type == "1":
        print("1. Configure your target server:")
        print("   smbreplay config show")
        print("   smbreplay config set server_ip <your-server-ip>")
        print("   smbreplay config set username <your-username>")
        print()
        print("2. Start using the tool:")
        print("   smbreplay list traces --case <case-id>")
        print("   smbreplay ingest --trace <pcap-file>")
        print("   smbreplay session --list")
        print("   smbreplay replay <session-id>")
        
    elif install_type == "2":
        print("1. Configure your target server (same as basic installation)")
        print("2. Test connectivity:")
        print("   python utils/tests/test_smb_connectivity.py")
        print("3. Use development tools:")
        print("   python utils/cleanup/cleanup_test_files.py")
        print("   python utils/tests/run_tests.py")
        
    else:  # install_type == "3"
        print("1. Configure your target server")
        print("2. Run code quality checks:")
        print("   black .")
        print("   flake8 .")
        print("   mypy .")
        print("3. Run tests:")
        print("   pytest")
    
    print("\n📖 For more information:")
    print("   - README.md - Usage guide")
    print("   - INSTALLATION.md - Detailed installation instructions")

def main():
    """Main installation function."""
    print_banner()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Get installation type
    install_type = get_installation_type()
    
    # Install package
    if not install_package(install_type):
        sys.exit(1)
    
    # Test installation
    if not test_installation():
        print("⚠️  Installation completed but tests failed")
        print("   You may need to check your configuration")
    
    # Show next steps
    show_next_steps(install_type)

if __name__ == "__main__":
    main() 