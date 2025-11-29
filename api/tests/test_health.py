"""Tests for health check endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestHealthEndpoints:
    """Tests for /health and /info endpoints."""

    def test_health_check_returns_ok(self, client: TestClient):
        """Test that health check returns OK status."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] in ["ok", "degraded", "error"]
        assert "version" in data
        assert "tshark_available" in data

    def test_health_check_includes_version(self, client: TestClient):
        """Test that health check includes version."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["version"] == "1.0.0"

    def test_system_info_returns_complete_data(self, client: TestClient):
        """Test that system info returns all expected fields."""
        response = client.get("/info")
        assert response.status_code == 200

        data = response.json()
        expected_fields = [
            "version",
            "tshark_available",
            "capture_path",
            "capture_valid",
            "supported_commands",
            "traces_folder",
            "verbosity_level",
        ]

        for field in expected_fields:
            assert field in data, f"Missing field: {field}"

    def test_root_endpoint(self, client: TestClient):
        """Test that root endpoint returns API info."""
        response = client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert data["name"] == "SMB Replay API"
        assert "version" in data
        assert "docs" in data
