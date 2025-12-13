"""
Database client for smbreplay to store session data in PostgreSQL.

This module provides async database operations to store trace and session data
in the tracer PostgreSQL database, replacing the Parquet file-based storage.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from .config import get_logger


def _make_json_serializable(data: Any) -> Any:
    """Recursively convert non-JSON-serializable types for database storage.

    Handles:
    - set -> list (from normalize_sesid/normalize_cmd in ingestion.py)
    - numpy int/float types -> Python int/float
    - numpy arrays -> lists
    - pd.Timestamp -> ISO format string
    - NaN/None values

    Args:
        data: Any data structure to convert

    Returns:
        JSON-serializable version of the data
    """
    if isinstance(data, dict):
        return {k: _make_json_serializable(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_make_json_serializable(v) for v in data]
    elif isinstance(data, set):
        return [_make_json_serializable(v) for v in data]
    elif isinstance(data, (np.integer,)):
        return int(data)
    elif isinstance(data, (np.floating,)):
        if np.isnan(data):
            return None
        return float(data)
    elif isinstance(data, np.ndarray):
        return [_make_json_serializable(v) for v in data.tolist()]
    elif isinstance(data, pd.Timestamp):
        return data.isoformat()
    elif pd.isna(data):
        return None
    return data

logger = get_logger()


class DatabaseClient:
    """Async PostgreSQL client for storing SMB replay session data."""

    def __init__(self, connection_string: Optional[str] = None):
        """Initialize database client.

        Args:
            connection_string: PostgreSQL connection string.
                             If None, reads from DATABASE_URL environment variable.
        """
        self.connection_string = connection_string or os.getenv(
            "DATABASE_URL",
            "postgresql://tracer:changeme@localhost:5432/tracer",
        )
        logger.info("Initialized database client")

    async def connect(self) -> psycopg.AsyncConnection:
        """Create async database connection.

        Returns:
            Async connection instance
        """
        conn = await psycopg.AsyncConnection.connect(
            self.connection_string, row_factory=dict_row
        )
        logger.debug("Created database connection")
        return conn

    async def create_or_update_trace(
        self,
        case_number: str,
        trace_name: str,
        capture_file_path: str,
        packet_count: Optional[int] = None,
        file_size: Optional[int] = None,
        status: str = "PENDING",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create or update a trace record.

        Args:
            case_number: Case number
            trace_name: Trace/PCAP file name
            capture_file_path: Full path to capture file
            packet_count: Number of packets in the trace
            file_size: File size in bytes
            status: Trace status (PENDING, INGESTING, COMPLETED, FAILED)
            metadata: Additional metadata as JSON

        Returns:
            Trace ID (UUID)
        """
        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                # Upsert trace record
                query = sql.SQL(
                    """
                    INSERT INTO "Trace"
                        ("caseNumber", "traceName", "captureFilePath",
                         "packetCount", "fileSize", status, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT ("caseNumber", "traceName")
                    DO UPDATE SET
                        "captureFilePath" = EXCLUDED."captureFilePath",
                        "packetCount" = EXCLUDED."packetCount",
                        "fileSize" = EXCLUDED."fileSize",
                        status = EXCLUDED.status,
                        metadata = EXCLUDED.metadata,
                        "updatedAt" = NOW()
                    RETURNING id
                    """
                )

                await cur.execute(
                    query,
                    (
                        case_number,
                        trace_name,
                        capture_file_path,
                        packet_count,
                        file_size,
                        status,
                        json.dumps(_make_json_serializable(metadata)) if metadata else None,
                    ),
                )
                result = await cur.fetchone()
                trace_id = result["id"]

                await conn.commit()
                logger.info(
                    f"Created/updated trace {trace_id} for {case_number}/{trace_name}"
                )
                return trace_id

    async def update_trace_status(
        self,
        trace_id: str,
        status: str,
        error_message: Optional[str] = None,
        ingested_at: Optional[datetime] = None,
    ):
        """Update trace ingestion status.

        Args:
            trace_id: Trace ID
            status: New status (PENDING, INGESTING, COMPLETED, FAILED)
            error_message: Error message if failed
            ingested_at: Timestamp when ingestion completed
        """
        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                query = sql.SQL(
                    """
                    UPDATE "Trace"
                    SET status = %s,
                        "errorMessage" = %s,
                        "ingestedAt" = %s,
                        "updatedAt" = NOW()
                    WHERE id = %s
                    """
                )

                await cur.execute(
                    query, (status, error_message, ingested_at, trace_id)
                )
                await conn.commit()
                logger.info(f"Updated trace {trace_id} status to {status}")

    async def create_session(
        self,
        trace_id: str,
        session_id: str,
        frames_df: pd.DataFrame,
        unique_commands: int = 0,
    ) -> str:
        """Create a session record with frame data.

        Args:
            trace_id: Parent trace ID
            session_id: SMB2 session ID (hex format)
            frames_df: DataFrame containing frame data
            unique_commands: Number of unique commands in session

        Returns:
            Session database ID (UUID)
        """
        # Convert DataFrame to JSON-serializable format
        # Uses _make_json_serializable to handle sets from normalize_sesid/normalize_cmd
        # and numpy types that json.dumps cannot serialize directly
        frames_data = _make_json_serializable(frames_df.to_dict(orient="records"))

        # Calculate statistics
        frame_count = len(frames_df)
        memory_mb = frames_df.memory_usage(deep=True).sum() / 1024**2

        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                query = sql.SQL(
                    """
                    INSERT INTO "Session"
                        ("traceId", "sessionId", "frameCount",
                         "uniqueCommands", "memoryMb", "framesData")
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT ("traceId", "sessionId")
                    DO UPDATE SET
                        "frameCount" = EXCLUDED."frameCount",
                        "uniqueCommands" = EXCLUDED."uniqueCommands",
                        "memoryMb" = EXCLUDED."memoryMb",
                        "framesData" = EXCLUDED."framesData",
                        "updatedAt" = NOW()
                    RETURNING id
                    """
                )

                await cur.execute(
                    query,
                    (
                        trace_id,
                        session_id,
                        frame_count,
                        unique_commands,
                        memory_mb,
                        json.dumps(frames_data),
                    ),
                )
                result = await cur.fetchone()
                db_session_id = result["id"]

                await conn.commit()
                logger.info(
                    f"Created session {session_id} ({frame_count} frames, {memory_mb:.2f}MB)"
                )
                return db_session_id

    async def get_trace_by_path(
        self, case_number: str, trace_name: str
    ) -> Optional[Dict[str, Any]]:
        """Get trace record by case number and trace name.

        Args:
            case_number: Case number
            trace_name: Trace name

        Returns:
            Trace record dict or None if not found
        """
        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                query = sql.SQL(
                    """
                    SELECT * FROM "Trace"
                    WHERE "caseNumber" = %s AND "traceName" = %s
                    """
                )

                await cur.execute(query, (case_number, trace_name))
                result = await cur.fetchone()
                return result

    async def list_sessions_for_trace(
        self, trace_id: str
    ) -> List[Dict[str, Any]]:
        """List all sessions for a trace.

        Args:
            trace_id: Trace ID

        Returns:
            List of session records (without frame data for efficiency)
        """
        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                query = sql.SQL(
                    """
                    SELECT id, "traceId", "sessionId", "frameCount",
                           "uniqueCommands", "memoryMb", "createdAt", "updatedAt"
                    FROM "Session"
                    WHERE "traceId" = %s
                    ORDER BY "createdAt" ASC
                    """
                )

                await cur.execute(query, (trace_id,))
                results = await cur.fetchall()
                return results

    async def get_session_frames(
        self, trace_id: str, session_id: str
    ) -> Optional[pd.DataFrame]:
        """Get frame data for a specific session.

        Args:
            trace_id: Trace ID
            session_id: SMB2 session ID

        Returns:
            DataFrame containing frame data or None if not found
        """
        async with await self.connect() as conn:
            async with conn.cursor() as cur:
                query = sql.SQL(
                    """
                    SELECT "framesData" FROM "Session"
                    WHERE "traceId" = %s AND "sessionId" = %s
                    """
                )

                await cur.execute(query, (trace_id, session_id))
                result = await cur.fetchone()

                if result:
                    frames_data = result["framesData"]
                    df = pd.DataFrame(frames_data)
                    logger.info(
                        f"Retrieved {len(df)} frames for session {session_id}"
                    )
                    return df
                return None


# Singleton instance
_db_client: Optional[DatabaseClient] = None


def get_database_client() -> DatabaseClient:
    """Get or create the global database client instance.

    Returns:
        DatabaseClient instance
    """
    global _db_client
    if _db_client is None:
        _db_client = DatabaseClient()
    return _db_client
