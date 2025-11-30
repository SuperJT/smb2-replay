"""Tests for session management endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestSessionEndpoints:
    """Tests for /api/sessions endpoints."""

    def test_list_sessions_returns_list(self, client: TestClient):
        """Test that list sessions returns a list."""
        response = client.get("/api/sessions")
        assert response.status_code == 200

        data = response.json()
        assert "sessions" in data
        assert "total" in data
        assert isinstance(data["sessions"], list)

    def test_list_sessions_with_capture_path(self, client: TestClient):
        """Test listing sessions with capture path override."""
        response = client.get("/api/sessions?capture_path=/test/capture.pcap")
        assert response.status_code == 200
        assert "sessions" in response.json()

    def test_list_sessions_session_structure(self, client: TestClient):
        """Test that each session has expected fields."""
        response = client.get("/api/sessions")
        assert response.status_code == 200

        data = response.json()
        if data["sessions"]:
            session = data["sessions"][0]
            assert "session_id" in session
            assert "file_name" in session

    def test_get_session_returns_operations(self, client: TestClient):
        """Test getting a specific session returns operations."""
        response = client.get("/api/sessions/0x1234567890abcdef")
        assert response.status_code == 200

        data = response.json()
        assert "session_id" in data
        assert "operations" in data
        assert "total" in data
        assert isinstance(data["operations"], list)

    def test_get_session_with_file_filter(self, client: TestClient):
        """Test getting session with file filter."""
        response = client.get(
            "/api/sessions/0x1234567890abcdef?file_filter=test\\file.txt"
        )
        assert response.status_code == 200
        assert "operations" in response.json()

    def test_get_session_not_found(self, client: TestClient):
        """Test getting non-existent session returns 404."""
        response = client.get("/api/sessions/notfound")
        assert response.status_code == 404

    def test_get_session_operations_post(self, client: TestClient):
        """Test getting operations via POST with complex filter."""
        response = client.post(
            "/api/sessions/0x1234567890abcdef/operations",
            json={
                "file_filter": "test\\file.txt",
                "fields": ["Frame", "Command", "Path"],
            },
        )
        assert response.status_code == 200

        data = response.json()
        assert "operations" in data
        assert data["file_filter"] == "test\\file.txt"

    def test_get_session_operations_post_not_found(self, client: TestClient):
        """Test POST operations for non-existent session."""
        response = client.post(
            "/api/sessions/notfound/operations",
            json={},
        )
        assert response.status_code == 404
