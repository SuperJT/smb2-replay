"""Tests for replay operation endpoints."""

from fastapi.testclient import TestClient


class TestReplayEndpoints:
    """Tests for /api/replay endpoints."""

    def test_validate_replay_success(self, client: TestClient):
        """Test successful replay validation."""
        response = client.post(
            "/api/replay/validate",
            json={"session_id": "0x1234567890abcdef"},
        )
        assert response.status_code == 200

        data = response.json()
        assert "ready" in data
        assert "checks" in data
        assert "errors" in data
        assert "warnings" in data

    def test_validate_replay_with_options(self, client: TestClient):
        """Test validation with specific check options."""
        response = client.post(
            "/api/replay/validate",
            json={
                "session_id": "0x1234567890abcdef",
                "check_fs": True,
                "check_ops": True,
            },
        )
        assert response.status_code == 200
        assert response.json()["ready"] is True

    def test_validate_replay_session_not_found(self, client: TestClient):
        """Test validation for non-existent session."""
        response = client.post(
            "/api/replay/validate",
            json={"session_id": "notfound"},
        )
        assert response.status_code == 404

    def test_validate_replay_missing_session_id(self, client: TestClient):
        """Test validation without session_id returns error."""
        response = client.post("/api/replay/validate", json={})
        assert response.status_code == 422

    def test_setup_infrastructure_success(self, client: TestClient):
        """Test successful infrastructure setup."""
        response = client.post(
            "/api/replay/setup",
            json={"session_id": "0x1234567890abcdef"},
        )
        assert response.status_code == 200

        data = response.json()
        assert "success" in data
        assert "directories_created" in data
        assert "files_created" in data
        assert data["success"] is True

    def test_setup_infrastructure_dry_run(self, client: TestClient):
        """Test infrastructure setup with dry run."""
        response = client.post(
            "/api/replay/setup",
            json={
                "session_id": "0x1234567890abcdef",
                "dry_run": True,
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert data["dry_run"] is True

    def test_setup_infrastructure_with_server_override(self, client: TestClient):
        """Test setup with server configuration override."""
        response = client.post(
            "/api/replay/setup",
            json={
                "session_id": "0x1234567890abcdef",
                "server_ip": "10.0.0.1",
                "username": "admin",
                "tree_name": "override_share",
            },
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_setup_infrastructure_session_not_found(self, client: TestClient):
        """Test setup for non-existent session."""
        response = client.post(
            "/api/replay/setup",
            json={"session_id": "notfound"},
        )
        assert response.status_code == 404

    def test_execute_replay_success(self, client: TestClient):
        """Test successful replay execution."""
        response = client.post(
            "/api/replay/execute",
            json={"session_id": "0x1234567890abcdef"},
        )
        assert response.status_code == 200

        data = response.json()
        assert "success" in data
        assert "total_operations" in data
        assert "successful_operations" in data
        assert "failed_operations" in data
        assert data["success"] is True

    def test_execute_replay_with_validation(self, client: TestClient):
        """Test replay with pre-validation enabled."""
        response = client.post(
            "/api/replay/execute",
            json={
                "session_id": "0x1234567890abcdef",
                "validate_first": True,
            },
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_execute_replay_without_ping(self, client: TestClient):
        """Test replay with ping disabled."""
        response = client.post(
            "/api/replay/execute",
            json={
                "session_id": "0x1234567890abcdef",
                "enable_ping": False,
            },
        )
        assert response.status_code == 200

    def test_execute_replay_with_server_override(self, client: TestClient):
        """Test replay with server configuration override."""
        response = client.post(
            "/api/replay/execute",
            json={
                "session_id": "0x1234567890abcdef",
                "server_ip": "10.0.0.1",
                "domain": "NEWDOMAIN",
                "username": "admin",
                "password": "secret",
                "tree_name": "override_share",
            },
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_execute_replay_session_not_found(self, client: TestClient):
        """Test replay for non-existent session."""
        response = client.post(
            "/api/replay/execute",
            json={"session_id": "notfound"},
        )
        assert response.status_code == 404

    def test_execute_replay_missing_session_id(self, client: TestClient):
        """Test replay without session_id returns error."""
        response = client.post("/api/replay/execute", json={})
        assert response.status_code == 422
