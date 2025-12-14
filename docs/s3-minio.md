## Architecture with MinIO/S3

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   smbreplay     │────▶│   PostgreSQL    │     │   MinIO/S3      │
│   (Python)      │     │   (metadata)    │     │   (frame data)  │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                       │                       ▲
        │                       │ framesPath            │
        └───────────────────────┼───────────────────────┘
                                │   "s3://sessions/{id}/frames.parquet"
```

## Benefits

| Feature        | PostgreSQL BYTEA | MinIO/S3                     |
| -------------- | ---------------- | ---------------------------- |
| Max size       | ~1GB             | Unlimited                    |
| Range reads    | No               | Yes (byte ranges)            |
| Streaming      | No               | Yes                          |
| CDN/caching    | No               | Yes                          |
| Versioning     | Manual           | Built-in                     |
| Cost           | DB storage $$    | Object storage $             |
| Presigned URLs | No               | Yes (direct client download) |

## Simple MinIO Setup

Add to `docker-compose.yml`:

```yaml
services:
  minio:
    image: minio/minio:latest
    container_name: tracer-ts-minio
    command: server /data --console-address ":9001"
    ports:
      - '9000:9000' # API
      - '9001:9001' # Console
    environment:
      - MINIO_ROOT_USER=${MINIO_ROOT_USER:-minioadmin}
      - MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD:-minioadmin}
    volumes:
      - minio-data:/data
    healthcheck:
      test: ['CMD', 'mc', 'ready', 'local']
      interval: 10s
      timeout: 5s
      retries: 3

volumes:
  minio-data:
```

## Prisma Schema

```prisma
model Session {
  id              String    @id @default(uuid())
  traceId         String
  sessionId       String    @db.VarChar(18)
  frameCount      Int

  // Stats (queryable in DB)
  uniqueCommands  Int       @default(0)
  firstTimestamp  DateTime?
  lastTimestamp   DateTime?
  commandSummary  Json?     @db.JsonB  // Small: {READ: 500, WRITE: 200}

  // S3 reference (no frame data in DB)
  framesObjectKey String?   // "sessions/{id}/frames.parquet"
  framesSizeBytes BigInt?

  createdAt       DateTime  @default(now())
  updatedAt       DateTime  @updatedAt

  trace           Trace     @relation(...)
}
```

## Python Client (smbreplay)

```python
import boto3
from io import BytesIO

class FrameStorage:
    def __init__(self, endpoint: str, access_key: str, secret_key: str, bucket: str = "sessions"):
        self.s3 = boto3.client(
            's3',
            endpoint_url=endpoint,  # http://minio:9000
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        self.bucket = bucket
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            self.s3.head_bucket(Bucket=self.bucket)
        except:
            self.s3.create_bucket(Bucket=self.bucket)

    def save_frames(self, session_id: str, parquet_bytes: bytes) -> str:
        key = f"{session_id}/frames.parquet"
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=parquet_bytes)
        return key

    def get_frames(self, object_key: str) -> bytes:
        response = self.s3.get_object(Bucket=self.bucket, Key=object_key)
        return response['Body'].read()

    def get_frames_range(self, object_key: str, start: int, end: int) -> bytes:
        """Fetch byte range (for streaming/pagination)."""
        response = self.s3.get_object(
            Bucket=self.bucket,
            Key=object_key,
            Range=f"bytes={start}-{end}"
        )
        return response['Body'].read()
```

## Env Config

```bash
# .env
MINIO_ENDPOINT=http://minio:9000
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=changeme
MINIO_BUCKET=sessions
```

## Flow

1. **Ingestion**: smbreplay extracts frames → writes parquet to MinIO → stores `framesObjectKey` in PostgreSQL
2. **Replay**: Fetch session from PostgreSQL → get `framesObjectKey` → stream parquet from MinIO
3. **Cleanup**: Delete session → delete S3 object

Want me to add MinIO to the docker-compose and update the schema?
