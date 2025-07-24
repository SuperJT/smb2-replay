#!/usr/bin/env python3
"""
Setup script for SMB2 Replay System
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements(filename):
    with open(filename, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="smbreplay",
    version="1.0.0",
    author="SMBReplay Team",
    description="SMB2 Replay System - Capture, analyze, and replay SMB2 traffic",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/SuperJT/smb2-replay",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "dev": [
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
        "dev-tools": [
            "smbprotocol>=1.5.0",
            "pandas>=1.3.0",
            "pyarrow>=7.0.0",
            "pytest>=7.0.0",
            "paramiko>=3.0.0",
            "scapy>=2.4.0",
        ],
        "dev-full": [
            "smbreplay[dev,dev-tools]",
        ],
    },
    entry_points={
        "console_scripts": [
            "smbreplay=smbreplay.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.txt", "*.md"],
        # Include utils directory only when installing with dev-tools
        "smbreplay": ["utils/**/*"] if os.environ.get("INSTALL_DEV_TOOLS") else [],
    },
)
