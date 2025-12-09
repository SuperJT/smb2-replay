#!/usr/bin/env python3
"""
Install Development Tools for SMB2 Replay System

This script installs the development tools and utilities that are not needed
for basic usage but are useful for development, debugging, and advanced analysis.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 12):
        print(f"❌ Python 3.12 or higher is required")
        print(f"   Current version: {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
        sys.exit(1)
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")

def check_package_manager():
    """Check if UV or pip is available."""
    has_uv = shutil.which("uv") is not None
    has_pip = shutil.which("pip") is not None

    if has_uv:
        uv_result = subprocess.run(["uv", "--version"], capture_output=True, text=True)
        print(f"✅ UV detected: {uv_result.stdout.strip()}")
        print("   (10-100x faster than pip)")
        return "uv"
    elif has_pip:
        print("✅ pip is available")
        print("   💡 For better performance, install UV: curl -LsSf https://astral.sh/uv/install.sh | sh")
        return "pip"
    else:
        print("❌ Neither UV nor pip is available")
        sys.exit(1)

def install_dev_tools():
    """Install development tools."""
    print("\n🔧 Installing development tools...")

    # Determine which package manager to use
    pkg_manager = check_package_manager()

    # Set environment variable to include utils in package data
    env = os.environ.copy()
    env["INSTALL_DEV_TOOLS"] = "1"

    try:
        if pkg_manager == "uv":
            cmd = ["uv", "sync", "--extra", "dev-tools"]
        else:  # pip
            cmd = [sys.executable, "-m", "pip", "install", "-e", ".[dev-tools]"]

        print(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, env=env, check=True, capture_output=True, text=True)

        print("✅ Development tools installed successfully!")
        return True

    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False

def copy_utils_directory():
    """Copy utils directory to the installed package."""
    print("\n📁 Copying development utilities...")

    # Get the package directory
    try:
        import smbreplay
        package_dir = Path(smbreplay.__file__).parent
        utils_dest = package_dir / "utils"

        # Copy utils directory
        utils_src = Path("utils")
        if utils_src.exists():
            if utils_dest.exists():
                shutil.rmtree(utils_dest)
            shutil.copytree(utils_src, utils_dest)
            print(f"✅ Utils copied to: {utils_dest}")
            return True
        else:
            print("❌ Utils directory not found")
            return False

    except ImportError:
        print("❌ Could not import smbreplay package")
        return False

def create_dev_scripts():
    """Create convenient scripts for development tools."""
    print("\n📝 Creating development scripts...")

    scripts_dir = Path("scripts")
    scripts_dir.mkdir(exist_ok=True)

    # Create test connectivity script
    test_connectivity = scripts_dir / "test_connectivity.py"
    test_connectivity.write_text('''#!/usr/bin/env python3
"""
Test SMB connectivity using your configuration.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'utils', 'tests'))

from test_smb_connectivity import main

if __name__ == "__main__":
    main()
''')

    # Create cleanup script
    cleanup_script = scripts_dir / "cleanup_test_files.py"
    cleanup_script.write_text('''#!/usr/bin/env python3
"""
Clean up test files from SMB server.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'utils', 'cleanup'))

from cleanup_test_files import cleanup_test_files

if __name__ == "__main__":
    cleanup_test_files()
''')

    # Make scripts executable
    for script in [test_connectivity, cleanup_script]:
        script.chmod(0o755)

    print(f"✅ Development scripts created in: {scripts_dir}")
    return True

def main():
    """Main installation function."""
    print("🚀 SMB2 Replay Development Tools Installer")
    print("=" * 50)

    # Pre-flight checks
    check_python_version()

    # Install development tools
    if not install_dev_tools():
        sys.exit(1)

    # Copy utils directory
    if not copy_utils_directory():
        print("⚠️  Warning: Could not copy utils directory")

    # Create development scripts
    if not create_dev_scripts():
        print("⚠️  Warning: Could not create development scripts")

    print("\n🎉 Development tools installation complete!")
    print("\n📋 Available development tools:")
    print("  • scripts/test_connectivity.py - Test SMB connectivity")
    print("  • scripts/cleanup_test_files.py - Clean up test files")
    print("  • utils/tests/ - Comprehensive test suite")
    print("  • utils/analysis/ - Advanced analysis tools")
    print("  • utils/benchmarks/ - Performance testing tools")
    print("  • utils/cleanup/ - File cleanup utilities")
    print("  • utils/pcap/ - PCAP capture tools")

    print("\n💡 Usage examples:")
    print("  python scripts/test_connectivity.py")
    print("  python scripts/cleanup_test_files.py")
    print("  python utils/tests/test_smb_connectivity.py")
    print("  python utils/cleanup/cleanup_test_files.py")

if __name__ == "__main__":
    main()
