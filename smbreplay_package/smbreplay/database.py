"""
Database client for smbreplay to store session data in PostgreSQL.

This module provides async database operations to store trace and session data
in the tracer PostgreSQL database, replacing the Parquet file-based storage.
"""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import numpy as np
import pandas as pd
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .config import get_logger


def _sanitize_connection_string(conn_string: str) -> tuple[str, str | None]:
    """Remove Prisma-specific query parameters from PostgreSQL connection string.

    Prisma uses `?schema=name` to specify the PostgreSQL schema, but psycopg3
    doesn't recognize this parameter. This function extracts it so we can set
    search_path manually after connecting.

    Args:
        conn_string: PostgreSQL connection string (possibly with Prisma params)

    Returns:
        Tuple of (sanitized_connection_string, schema_name or None)
    """
    parsed = urlparse(conn_string)
    query_params = parse_qs(parsed.query)

    # Extract schema if present
    schema = query_params.pop("schema", [None])[0]

    # Rebuild query string without schema parameter
    new_query = urlencode(query_params, doseq=True)

    # Reconstruct the URL
    sanitized = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )

    return sanitized, schema


# Module-level connection pool (singleton pattern)
_pool: AsyncConnectionPool | None = None
_pool_lock: asyncio.Lock | None = None  # Lazy-initialized async lock


def _get_pool_lock() -> asyncio.Lock:
    """Get or create the pool lock (must be called from async context)."""
    global _pool_lock
    if _pool_lock is None:
        _pool_lock = asyncio.Lock()
    return _pool_lock


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
    elif isinstance(data, (list, set)):
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
    """Async PostgreSQL client for storing SMB replay session data.

    Uses connection pooling for efficient connection management.
    """

    # Default pool configuration
    MIN_POOL_SIZE = 2
    MAX_POOL_SIZE = 10
    CONNECTION_TIMEOUT = 30.0  # seconds
    QUERY_TIMEOUT = 60.0  # seconds

    def __init__(
        self,
        connection_string: str | None = None,
        min_size: int = MIN_POOL_SIZE,
        max_size: int = MAX_POOL_SIZE,
        connection_timeout: float = CONNECTION_TIMEOUT,
        query_timeout: float = QUERY_TIMEOUT,
    ):
        """Initialize database client with connection pool.

        Args:
            connection_string: PostgreSQL connection string.
                             If None, reads from DATABASE_URL environment variable.
            min_size: Minimum number of connections in pool (default 2)
            max_size: Maximum number of connections in pool (default 10)
            connection_timeout: Timeout for acquiring connection from pool (default 30s)
            query_timeout: Timeout for query execution (default 60s)
        """
        raw_conn_string = connection_string or os.getenv("DATABASE_URL") or ""

        # Sanitize connection string to remove Prisma-specific params
        self.connection_string, self._schema = _sanitize_connection_string(
            raw_conn_string
        )

        self.min_size = min_size
        self.max_size = max_size
        self.connection_timeout = connection_timeout
        self.query_timeout = query_timeout
        self._pool: AsyncConnectionPool | None = None

        schema_info = f", schema={self._schema}" if self._schema else ""
        logger.info(
            f"Initialized database client (pool: min={min_size}, max={max_size}, "
            f"conn_timeout={connection_timeout}s, query_timeout={query_timeout}s{schema_info})"
        )

    async def _get_pool(self) -> AsyncConnectionPool:
        """Get or create the connection pool (lazy initialization).

        Returns:
            The async connection pool

        Note:
            Uses async lock to prevent race condition where multiple coroutines
            could see _pool as None and create duplicate pools.
        """
        global _pool
        # Fast path: pool already exists
        if _pool is not None:
            return _pool

        # Slow path: acquire lock and create pool if still needed
        async with _get_pool_lock():
            # Double-check after acquiring lock
            if _pool is None:
                # Create configure callback if schema is specified
                # This sets search_path on each new connection (Prisma compatibility)
                configure = None
                if self._schema:
                    # Capture schema in local variable for closure
                    schema = self._schema

                    async def configure(conn: Any) -> None:
                        await conn.execute(
                            sql.SQL("SET search_path TO {}").format(
                                sql.Identifier(schema)
                            )
                        )

                _pool = AsyncConnectionPool(
                    self.connection_string,
                    min_size=self.min_size,
                    max_size=self.max_size,
                    timeout=self.connection_timeout,
                    kwargs={"row_factory": dict_row},
                    configure=configure,
                    open=False,  # Don't open immediately
                )
                await _pool.open()
                schema_msg = f" (schema: {self._schema})" if self._schema else ""
                logger.info(f"Database connection pool opened{schema_msg}")
            return _pool

    @asynccontextmanager
    async def connect(self):
        """Get a connection from the pool with automatic transaction management.

        Yields:
            Async connection instance from the pool

        The connection automatically commits on success or rolls back on exception.

        Usage:
            async with client.connect() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(...)
        """
        pool = await self._get_pool()
        async with pool.connection() as conn:
            logger.debug("Acquired connection from pool")
            try:
                yield conn
                await conn.commit()
                logger.debug("Transaction committed")
            except Exception as e:
                await conn.rollback()
                logger.error(f"Transaction rolled back due to error: {e}")
                raise
            finally:
                logger.debug("Released connection to pool")

    async def close(self):
        """Close the connection pool."""
        global _pool
        async with _get_pool_lock():
            if _pool is not None:
                await _pool.close()
                _pool = None
                logger.info("Database connection pool closed")

    async def create_or_update_trace(
        self,
        case_number: str,
        trace_name: str,
        capture_file_path: str,
        packet_count: int | None = None,
        file_size: int | None = None,
        status: str = "PENDING",
        metadata: dict[str, Any] | None = None,
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
        async with self.connect() as conn, conn.cursor() as cur:
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
        error_message: str | None = None,
        ingested_at: datetime | None = None,
    ):
        """Update trace ingestion status.

        Args:
            trace_id: Trace ID
            status: New status (PENDING, INGESTING, COMPLETED, FAILED)
            error_message: Error message if failed
            ingested_at: Timestamp when ingestion completed
        """
        async with self.connect() as conn, conn.cursor() as cur:
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

            await cur.execute(query, (status, error_message, ingested_at, trace_id))
            await conn.commit()
            logger.info(f"Updated trace {trace_id} status to {status}")

    async def create_session(
        self,
        trace_id: str,
        session_id: str,
        frame_count: int,
        unique_commands: int = 0,
        memory_mb: float = 0.0,
        frames_object_key: str | None = None,
        frames_size_bytes: int | None = None,
    ) -> str:
        """Create a session record with S3 object reference.

        Frame data is stored in S3, not in the database. This method stores
        only metadata and the S3 object key for later retrieval.

        Args:
            trace_id: Parent trace ID
            session_id: SMB2 session ID (hex format)
            frame_count: Number of frames in session
            unique_commands: Number of unique commands in session
            memory_mb: Memory usage in MB
            frames_object_key: S3 object key for frame data
            frames_size_bytes: Size of Parquet file in bytes

        Returns:
            Session database ID (UUID)
        """
        async with self.connect() as conn, conn.cursor() as cur:
            query = sql.SQL(
                """
                INSERT INTO "Session"
                    ("traceId", "sessionId", "frameCount",
                     "uniqueCommands", "memoryMb",
                     "framesObjectKey", "framesSizeBytes")
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT ("traceId", "sessionId")
                DO UPDATE SET
                    "frameCount" = EXCLUDED."frameCount",
                    "uniqueCommands" = EXCLUDED."uniqueCommands",
                    "memoryMb" = EXCLUDED."memoryMb",
                    "framesObjectKey" = EXCLUDED."framesObjectKey",
                    "framesSizeBytes" = EXCLUDED."framesSizeBytes",
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
                    frames_object_key,
                    frames_size_bytes,
                ),
            )
            result = await cur.fetchone()
            db_session_id = result["id"]

            await conn.commit()
            logger.info(
                f"Created session {session_id} ({frame_count} frames, "
                f"key={frames_object_key})"
            )
            return db_session_id

    async def get_trace_by_path(
        self, case_number: str, trace_name: str
    ) -> dict[str, Any] | None:
        """Get trace record by case number and trace name.

        Args:
            case_number: Case number
            trace_name: Trace name

        Returns:
            Trace record dict or None if not found
        """
        async with self.connect() as conn, conn.cursor() as cur:
            query = sql.SQL(
                """
                    SELECT * FROM "Trace"
                    WHERE "caseNumber" = %s AND "traceName" = %s
                    """
            )

            await cur.execute(query, (case_number, trace_name))
            result = await cur.fetchone()
            return result

    async def list_sessions_for_trace(self, trace_id: str) -> list[dict[str, Any]]:
        """List all sessions for a trace.

        Args:
            trace_id: Trace ID

        Returns:
            List of session records (without frame data for efficiency)
        """
        async with self.connect() as conn, conn.cursor() as cur:
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

    async def get_session_object_key(
        self, trace_id: str, session_id: str
    ) -> str | None:
        """Get S3 object key for a session's frames.

        Args:
            trace_id: Trace ID
            session_id: SMB2 session ID

        Returns:
            S3 object key or None if not found
        """
        async with self.connect() as conn, conn.cursor() as cur:
            query = sql.SQL(
                """
                    SELECT "framesObjectKey" FROM "Session"
                    WHERE "traceId" = %s AND "sessionId" = %s
                    """
            )

            await cur.execute(query, (trace_id, session_id))
            result = await cur.fetchone()

            if result:
                return result["framesObjectKey"]
            return None

    async def delete_session(self, trace_id: str, session_id: str) -> str | None:
        """Delete a session and return its S3 object key for cleanup.

        Args:
            trace_id: Trace ID
            session_id: Session ID

        Returns:
            S3 object key that should be deleted, or None
        """
        async with self.connect() as conn, conn.cursor() as cur:
            # Get object key before deleting
            query = sql.SQL(
                """
                DELETE FROM "Session"
                WHERE "traceId" = %s AND "sessionId" = %s
                RETURNING "framesObjectKey"
                """
            )

            await cur.execute(query, (trace_id, session_id))
            result = await cur.fetchone()
            await conn.commit()

            if result:
                logger.info(f"Deleted session {session_id}")
                return result["framesObjectKey"]
            return None


# Singleton instance
_db_client: DatabaseClient | None = None


def get_database_client() -> DatabaseClient:
    """Get or create the global database client instance.

    Returns:
        DatabaseClient instance
    """
    global _db_client
    if _db_client is None:
        _db_client = DatabaseClient()
    return _db_client
