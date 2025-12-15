"""Pytest configuration and fixtures for API tests."""

import os
import sys
from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

# Add paths for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "..", "smbreplay_package")
)


class MockSMB2ReplaySystem:
    """Mock implementation of SMB2ReplaySystem for testing."""

    def __init__(self):
        self.config = MockConfigManager()
        self._session_manager = None

    def setup_system(self) -> bool:
        return True

    def setup_system_full(self) -> bool:
        return True

    def get_system_info(self) -> dict[str, Any]:
        return {
            "tshark_available": True,
            "capture_path": "/test/capture.pcap",
            "capture_valid": True,
            "supported_commands": {"0": "Negotiate", "5": "Create", "6": "Close"},
            "traces_folder": "/stingray",
            "verbosity_level": 0,
            "packet_count": 1000,
        }

    def list_traces(self, case_id: str | None = None) -> list[str]:
        return ["trace1.pcap", "trace2.pcapng", "subdir/trace3.pcap"]

    def list_sessions(self, capture_path: str | None = None) -> list[str]:
        return [
            "smb2_session_0x1234567890abcdef.parquet",
            "smb2_session_0xfedcba0987654321.parquet",
        ]

    def get_session_info(
        self,
        session_file: str,
        capture_path: str | None = None,
        file_filter: str | None = None,
        fields: list[str] | None = None,
    ) -> list[dict[str, Any]] | None:
        if "notfound" in session_file:
            return None
        return [
            {
                "Frame": "1",
                "Command": "Create",
                "Path": "test\\file.txt",
                "Status": "STATUS_SUCCESS",
                "StatusDesc": "The operation completed successfully",
                "Tree": "\\\\server\\share",
            },
            {
                "Frame": "2",
                "Command": "Write",
                "Path": "test\\file.txt",
                "Status": "STATUS_SUCCESS",
                "StatusDesc": "The operation completed successfully",
                "Tree": "\\\\server\\share",
            },
        ]

    def ingest_pcap(
        self,
        pcap_path: str,
        force_reingest: bool = False,
        reassembly: bool = False,
        verbose: bool = False,
    ) -> dict[str, Any] | None:
        if "invalid" in pcap_path:
            return None
        # Return format matches real _run_ingestion output
        return {
            "sessions": {"0x1234": None},  # Dict of session_id -> DataFrame
            "performance": {
                "processing_time": 2.5,
                "packets_processed": 500,
            },
        }

    async def ingest_pcap_async(
        self,
        pcap_path: str,
        force_reingest: bool = False,
        reassembly: bool = False,
        verbose: bool = False,
    ) -> dict[str, Any] | None:
        """Async version of ingest_pcap for use with FastAPI endpoints."""
        if "invalid" in pcap_path:
            return None
        # Return format matches real _run_ingestion output
        return {
            "sessions": {"0x1234": None},  # Dict of session_id -> DataFrame
            "performance": {
                "processing_time": 2.5,
                "packets_processed": 500,
            },
        }

    def validate_replay_readiness(
        self,
        operations: list[dict[str, Any]],
        check_fs: bool = True,
        check_ops: bool = True,
    ) -> dict[str, Any]:
        return {
            "ready": True,
            "checks": {
                "operations": {
                    "valid": True,
                    "total_operations": len(operations),
                    "supported_operations": len(operations),
                    "issues": [],
                },
                "file_system": {
                    "ready": True,
                    "total_paths": 2,
                    "missing_directories": [],
                    "warnings": [],
                },
            },
            "errors": [],
            "warnings": [],
        }

    def setup_file_system_infrastructure(
        self,
        operations: list[dict[str, Any]],
        dry_run: bool = False,
        force: bool = False,
    ) -> dict[str, Any]:
        return {
            "success": True,
            "directories_created": 3,
            "files_created": 5,
            "errors": [],
            "warnings": [],
            "dry_run": dry_run,
        }

    def replay_operations(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "success": True,
            "total_operations": len(operations),
            "successful_operations": len(operations),
            "failed_operations": 0,
            "errors": [],
        }

    def configure_replay(self, **kwargs):
        pass

    def set_verbosity(self, level: int):
        pass


class MockConfigManager:
    """Mock implementation of ConfigManager for testing."""

    def __init__(self):
        self._config = {
            "traces_folder": "/stingray",
            "capture_path": "/test/capture.pcap",
            "verbosity_level": 0,
            "session_id": "0x1234567890abcdef",
            "case_id": "2010101010",
            "trace_name": "capture.pcap",
            "server_ip": "192.168.1.100",
            "port": 445,
            "domain": "TESTDOMAIN",
            "username": "testuser",
            "password": "testpass",
            "tree_name": "testshare",
            "max_wait": 5.0,
        }

    def get_traces_folder(self) -> str:
        return self._config["traces_folder"]

    def set_traces_folder(self, path: str):
        self._config["traces_folder"] = path

    def get_capture_path(self) -> str | None:
        return self._config["capture_path"]

    def set_capture_path(self, path: str):
        self._config["capture_path"] = path

    def get_verbosity_level(self) -> int:
        return self._config["verbosity_level"]

    def get_session_id(self) -> str | None:
        return self._config["session_id"]

    def set_session_id(self, session_id: str):
        self._config["session_id"] = session_id

    def get_case_id(self) -> str | None:
        return self._config["case_id"]

    def set_case_id(self, case_id: str):
        self._config["case_id"] = case_id

    def get_trace_name(self) -> str | None:
        return self._config["trace_name"]

    def set_trace_name(self, name: str):
        self._config["trace_name"] = name

    def get_server_ip(self) -> str:
        return self._config["server_ip"]

    def get_port(self) -> int:
        return self._config["port"]

    def get_domain(self) -> str:
        return self._config["domain"]

    def get_username(self) -> str:
        return self._config["username"]

    def get_password(self) -> str:
        return self._config["password"]

    def get_tree_name(self) -> str:
        return self._config["tree_name"]

    def get_max_wait(self) -> float:
        return self._config["max_wait"]


@pytest.fixture
def mock_smb2_system():
    """Create a mock SMB2ReplaySystem."""
    return MockSMB2ReplaySystem()


@pytest.fixture
def mock_service(mock_smb2_system):
    """Create a mock SMBReplayService."""
    from api.services.smbreplay_service import SMBReplayService

    service = SMBReplayService()
    service._system = mock_smb2_system
    service._initialized = True
    return service


@pytest.fixture
def client(mock_service) -> Generator[TestClient, None, None]:
    """Create a test client with mocked service."""
    from api.main import app
    from api.services.smbreplay_service import get_smbreplay_service

    # Override the dependency
    app.dependency_overrides[get_smbreplay_service] = lambda: mock_service

    with TestClient(app) as test_client:
        yield test_client

    # Clean up
    app.dependency_overrides.clear()
