"""Tests for trace management endpoints."""

import pytest
from fastapi.testclient import TestClient


class TestTraceEndpoints:
    """Tests for /api/traces endpoints."""

    def test_list_traces_returns_list(self, client: TestClient):
        """Test that list traces returns a list of traces."""
        response = client.get("/api/traces")
        assert response.status_code == 200

        data = response.json()
        assert "traces" in data
        assert "total" in data
        assert isinstance(data["traces"], list)
        assert data["total"] == len(data["traces"])

    def test_list_traces_with_case_id(self, client: TestClient):
        """Test listing traces with specific case ID."""
        response = client.get("/api/traces?case_id=2010101010")
        assert response.status_code == 200

        data = response.json()
        assert "case_id" in data

    def test_list_traces_trace_structure(self, client: TestClient):
        """Test that each trace has expected fields."""
        response = client.get("/api/traces")
        assert response.status_code == 200

        data = response.json()
        if data["traces"]:
            trace = data["traces"][0]
            assert "path" in trace
            assert "name" in trace

    def test_ingest_trace_success(self, client: TestClient):
        """Test successful trace ingestion."""
        response = client.post(
            "/api/traces/ingest",
            json={"path": "/test/valid.pcap", "force": False, "reassembly": False},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is True
        assert "sessions" in data
        assert "session_count" in data

    def test_ingest_trace_with_force(self, client: TestClient):
        """Test trace ingestion with force flag."""
        response = client.post(
            "/api/traces/ingest",
            json={"path": "/test/valid.pcap", "force": True},
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_ingest_trace_with_reassembly(self, client: TestClient):
        """Test trace ingestion with TCP reassembly."""
        response = client.post(
            "/api/traces/ingest",
            json={"path": "/test/valid.pcap", "reassembly": True},
        )
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_ingest_trace_invalid_path(self, client: TestClient):
        """Test ingestion with invalid path returns failure."""
        response = client.post(
            "/api/traces/ingest",
            json={"path": "/test/invalid.pcap"},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["success"] is False
        assert "error" in data

    def test_ingest_trace_missing_path(self, client: TestClient):
        """Test ingestion without path returns validation error."""
        response = client.post("/api/traces/ingest", json={})
        assert response.status_code == 422  # Pydantic validation error
