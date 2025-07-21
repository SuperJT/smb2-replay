#!/usr/bin/env python3
"""
Setup script for SMB2 Replay System
"""

from setuptools import setup, find_packages
import os

# Read the version from the package
def get_version():
    """Get version from package __init__.py"""
    import re
    with open(os.path.join("smbreplay", "__init__.py"), "r") as f:
        content = f.read()
        # Extract version using regex instead of exec
        version_match = re.search(r'__version__\s*=\s*["\']([^"\']*)["\']', content)
        if version_match:
            return version_match.group(1)
        else:
            return "1.0.0"

# Read the long description from README
def get_long_description():
    """Get long description from README"""
    try:
        with open("../README.md", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "A comprehensive tool for capturing, analyzing, and replaying SMB2 network traffic"

# Read requirements
def get_requirements():
    """Get requirements from requirements.txt"""
    try:
        with open("../requirements.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return [
            "pandas>=2.0.0",
            "pyarrow>=10.0.0",
            "numpy>=1.24.0",
            "smbprotocol>=1.8.0",
            "paramiko>=3.0.0",
            "scapy>=2.5.0",
            "psutil>=5.9.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "click>=8.0.0",
            "argparse>=1.4.0",
            "python-dotenv>=1.0.0",
        ]

setup(
    name="smbreplay",
    version=get_version(),
    author="SMB2 Replay System",
    author_email="",
    description="A comprehensive tool for capturing, analyzing, and replaying SMB2 network traffic",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url="",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=get_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0.0",
            "pytest-cov>=2.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.900",
        ],
    },
    entry_points={
        "console_scripts": [
            "smbreplay=smbreplay.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "smbreplay": ["*.txt", "*.md"],
    },
    zip_safe=False,
)
