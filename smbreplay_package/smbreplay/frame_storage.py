"""S3/MinIO Frame Storage Module.

Handles storage and retrieval of session frame data in object storage.
Frame data is stored as Parquet files with zstd compression.
"""

from __future__ import annotations

import io
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import pandas as pd

from .config import get_logger

logger = get_logger()


class FrameStorageError(Exception):
    """Exception raised for frame storage errors."""

    def __init__(self, message: str, code: str | None = None) -> None:
        self.message = message
        self.code = code
        super().__init__(message)


class FrameStorage:
    """S3/MinIO client for storing session frame data as Parquet files."""

    def __init__(
        self,
        endpoint: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        bucket: str | None = None,
        region: str = "us-east-1",
    ) -> None:
        """Initialize frame storage client.

        Args:
            endpoint: S3 endpoint URL (e.g., http://minio:9000)
            access_key: AWS/MinIO access key
            secret_key: AWS/MinIO secret key
            bucket: Bucket name for frame storage
            region: AWS region (default us-east-1)
        """
        self.endpoint = endpoint or os.getenv("S3_ENDPOINT", "http://localhost:9000")
        self.access_key = access_key or os.getenv("S3_ACCESS_KEY", "minioadmin")
        self.secret_key = secret_key or os.getenv("S3_SECRET_KEY", "minioadmin")
        self.bucket = bucket or os.getenv("S3_BUCKET", "sessions")
        self.region = region

        self._client: Any = None
        logger.info(
            f"Initialized FrameStorage with endpoint={self.endpoint}, bucket={self.bucket}"
        )

    @property
    def client(self) -> Any:
        """Lazy-initialize S3 client."""
        if self._client is None:
            import boto3

            self._client = boto3.client(
                "s3",
                endpoint_url=self.endpoint,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
            self._ensure_bucket()
        return self._client

    def _ensure_bucket(self) -> None:
        """Ensure the bucket exists, create if not."""
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
            logger.debug(f"Bucket {self.bucket} exists")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("404", "NoSuchBucket"):
                logger.info(f"Creating bucket {self.bucket}")
                self._client.create_bucket(Bucket=self.bucket)
            else:
                raise FrameStorageError(
                    f"Failed to access bucket: {e}", code="BUCKET_ACCESS_ERROR"
                ) from e

    def generate_object_key(
        self, case_id: str, trace_name: str, session_id: str
    ) -> str:
        """Generate S3 object key for session frames.

        Args:
            case_id: Case identifier
            trace_name: Trace/PCAP name (without extension)
            session_id: SMB2 session ID

        Returns:
            Object key in format: {case_id}/{trace_name}/{session_id}.parquet
        """
        # Sanitize inputs - replace path separators
        safe_case = case_id.replace("/", "_").replace("\\", "_")
        # Remove extension from trace name
        safe_trace = trace_name.replace("/", "_").replace("\\", "_")
        if "." in safe_trace:
            safe_trace = safe_trace.rsplit(".", 1)[0]
        safe_session = session_id.replace("/", "_").replace("\\", "_")

        return f"{safe_case}/{safe_trace}/{safe_session}.parquet"

    def save_frames(
        self,
        case_id: str,
        trace_name: str,
        session_id: str,
        frames_df: pd.DataFrame,
    ) -> tuple[str, int]:
        """Save session frames to S3 as Parquet.

        Args:
            case_id: Case identifier
            trace_name: Trace name
            session_id: Session ID
            frames_df: DataFrame containing frame data

        Returns:
            Tuple of (object_key, size_bytes)
        """
        import pyarrow as pa
        import pyarrow.parquet as pq

        object_key = self.generate_object_key(case_id, trace_name, session_id)

        # Serialize DataFrame to Parquet bytes with zstd compression
        parquet_buffer = io.BytesIO()
        table = pa.Table.from_pandas(frames_df, preserve_index=False)
        pq.write_table(table, parquet_buffer, compression="zstd")
        parquet_bytes = parquet_buffer.getvalue()
        size_bytes = len(parquet_bytes)

        logger.info(f"Uploading {size_bytes} bytes to s3://{self.bucket}/{object_key}")

        from botocore.exceptions import ClientError

        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=object_key,
                Body=parquet_bytes,
                ContentType="application/octet-stream",
            )
            logger.info(f"Successfully uploaded frames to {object_key}")
            return object_key, size_bytes
        except ClientError as e:
            raise FrameStorageError(
                f"Failed to upload frames: {e}", code="UPLOAD_ERROR"
            ) from e

    def get_frames(self, object_key: str) -> pd.DataFrame:
        """Retrieve session frames from S3.

        Args:
            object_key: S3 object key

        Returns:
            DataFrame containing frame data
        """
        import pyarrow.parquet as pq

        logger.info(f"Downloading frames from s3://{self.bucket}/{object_key}")

        from botocore.exceptions import ClientError

        try:
            response = self.client.get_object(Bucket=self.bucket, Key=object_key)
            parquet_bytes = response["Body"].read()

            parquet_buffer = io.BytesIO(parquet_bytes)
            table = pq.read_table(parquet_buffer)
            df: pd.DataFrame = table.to_pandas()

            logger.info(f"Retrieved {len(df)} frames from {object_key}")
            return df
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("404", "NoSuchKey"):
                raise FrameStorageError(
                    f"Frames not found: {object_key}", code="NOT_FOUND"
                ) from e
            raise FrameStorageError(
                f"Failed to retrieve frames: {e}", code="DOWNLOAD_ERROR"
            ) from e

    def delete_frames(self, object_key: str) -> bool:
        """Delete session frames from S3.

        Args:
            object_key: S3 object key

        Returns:
            True if deleted successfully
        """
        logger.info(f"Deleting frames at s3://{self.bucket}/{object_key}")

        from botocore.exceptions import ClientError

        try:
            self.client.delete_object(Bucket=self.bucket, Key=object_key)
            logger.info(f"Deleted {object_key}")
            return True
        except ClientError as e:
            logger.error(f"Failed to delete {object_key}: {e}")
            return False

    def delete_trace_frames(self, case_id: str, trace_name: str) -> int:
        """Delete all frames for a trace (when trace is deleted).

        Args:
            case_id: Case identifier
            trace_name: Trace name

        Returns:
            Number of objects deleted
        """
        # Sanitize and build prefix
        safe_case = case_id.replace("/", "_").replace("\\", "_")
        safe_trace = trace_name.replace("/", "_").replace("\\", "_")
        if "." in safe_trace:
            safe_trace = safe_trace.rsplit(".", 1)[0]
        prefix = f"{safe_case}/{safe_trace}/"

        logger.info(f"Deleting all frames with prefix: {prefix}")

        from botocore.exceptions import ClientError

        deleted_count = 0
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
                objects = page.get("Contents", [])
                if objects:
                    delete_keys = [{"Key": obj["Key"]} for obj in objects]
                    self.client.delete_objects(
                        Bucket=self.bucket, Delete={"Objects": delete_keys}
                    )
                    deleted_count += len(delete_keys)

            logger.info(f"Deleted {deleted_count} frame objects for {prefix}")
            return deleted_count
        except ClientError as e:
            logger.error(f"Failed to delete trace frames: {e}")
            return deleted_count

    def frames_exist(self, object_key: str) -> bool:
        """Check if frames exist in S3.

        Args:
            object_key: S3 object key

        Returns:
            True if object exists
        """
        from botocore.exceptions import ClientError

        try:
            self.client.head_object(Bucket=self.bucket, Key=object_key)
            return True
        except ClientError:
            return False


# Module-level singleton
_frame_storage: FrameStorage | None = None


def get_frame_storage() -> FrameStorage:
    """Get or create the global FrameStorage instance."""
    global _frame_storage
    if _frame_storage is None:
        _frame_storage = FrameStorage()
    return _frame_storage
