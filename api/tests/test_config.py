"""Tests for configuration endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestConfigEndpoints:
    """Tests for /api/config endpoints."""

    def test_get_config_returns_all_fields(self, client: TestClient):
        """Test that get config returns all configuration fields."""
        response = client.get("/api/config")
        assert response.status_code == 200

        data = response.json()
        expected_fields = [
            "traces_folder",
            "capture_path",
            "verbosity_level",
            "session_id",
            "case_id",
            "trace_name",
            "server_ip",
            "port",
            "domain",
            "username",
            "password_set",
            "tree_name",
            "max_wait",
        ]

        for field in expected_fields:
            assert field in data, f"Missing field: {field}"

    def test_get_config_password_is_masked(self, client: TestClient):
        """Test that password is not returned, only password_set flag."""
        response = client.get("/api/config")
        assert response.status_code == 200

        data = response.json()
        assert "password" not in data
        assert "password_set" in data
        assert isinstance(data["password_set"], bool)

    def test_update_config_partial(self, client: TestClient):
        """Test partial config update."""
        response = client.put(
            "/api/config",
            json={"server_ip": "10.0.0.1", "port": 4445},
        )
        assert response.status_code == 200

        data = response.json()
        assert "server_ip" in data
        assert "port" in data

    def test_update_config_empty_body(self, client: TestClient):
        """Test update with empty body returns current config."""
        response = client.put("/api/config", json={})
        assert response.status_code == 200
        assert "traces_folder" in response.json()

    def test_get_config_value_valid_key(self, client: TestClient):
        """Test getting a specific config value."""
        response = client.get("/api/config/server_ip")
        assert response.status_code == 200

        data = response.json()
        assert data["key"] == "server_ip"
        assert "value" in data

    def test_get_config_value_invalid_key(self, client: TestClient):
        """Test getting an invalid config key returns error."""
        response = client.get("/api/config/invalid_key")
        assert response.status_code == 400

    def test_update_config_validates_port(self, client: TestClient):
        """Test that port validation works."""
        # Valid port
        response = client.put("/api/config", json={"port": 445})
        assert response.status_code == 200

        # Invalid port (out of range) - should fail validation
        response = client.put("/api/config", json={"port": 70000})
        assert response.status_code == 422  # Pydantic validation error

    def test_update_config_validates_verbosity(self, client: TestClient):
        """Test that verbosity level validation works."""
        # Valid verbosity
        response = client.put("/api/config", json={"verbosity_level": 2})
        assert response.status_code == 200

        # Invalid verbosity (out of range)
        response = client.put("/api/config", json={"verbosity_level": 5})
        assert response.status_code == 422
