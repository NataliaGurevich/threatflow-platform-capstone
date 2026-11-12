"""Backend-neutral contract for immutable original source responses."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from threatflow.config import Settings

_SOURCE_EXTENSIONS = {"cisa_kev": {"json"}, "nvd": {"json"}, "epss": {"csv", "csv.gz"}}
_SAFE_SOURCE = re.compile(r"^[a-z][a-z0-9_]*$")
_CONTENT_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "csv.gz": "application/gzip",
}


@dataclass(frozen=True)
class RawArtifactRef:
    """Backend-neutral reference to one immutable raw artifact."""

    source: str
    sha256: str
    uri: str
    extension: str
    content_type: str
    size_bytes: int
    created: bool
    backend: str
    bucket: str | None = None
    object_key: str | None = None
    version_id: str | None = None

    @property
    def path(self) -> Path:
        """Return the local path while the compatibility API is in use."""
        if self.backend != "local":
            raise ValueError(f"artifact backend {self.backend!r} has no local path")
        return Path(self.uri)


# Compatibility name retained for repository and third-party imports.
RawArtifactResult = RawArtifactRef


class RawArtifactStore(Protocol):
    """Store and retrieve exact raw bytes without exposing backend SDK details."""

    backend: str

    def store(
        self,
        source: str,
        content: bytes,
        acquired_at: datetime,
        extension: str,
        *,
        content_type: str | None = None,
    ) -> RawArtifactRef: ...

    def read(self, artifact: RawArtifactRef | str) -> bytes: ...


def calculate_sha256(content: bytes) -> str:
    """Return the SHA-256 digest of the exact supplied bytes."""
    return hashlib.sha256(content).hexdigest()


def validate_raw_artifact_input(
    source: str,
    content: bytes,
    acquired_at: datetime,
    extension: str,
    content_type: str | None = None,
) -> tuple[str, str]:
    """Validate shared storage inputs and return normalized extension and content type."""
    if not isinstance(source, str) or not _SAFE_SOURCE.fullmatch(source):
        raise ValueError("source must contain only lowercase letters, digits, and underscores")
    if source not in _SOURCE_EXTENSIONS:
        raise ValueError(f"unsupported source: {source}")
    normalized_extension = extension.removeprefix(".").lower()
    if normalized_extension not in _SOURCE_EXTENSIONS[source]:
        raise ValueError(f"unsupported extension for {source}: {extension}")
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if not isinstance(acquired_at, datetime):
        raise TypeError("acquired_at must be a datetime")
    return normalized_extension, content_type or _CONTENT_TYPES[normalized_extension]


def supported_raw_sources() -> tuple[str, ...]:
    """Return source names accepted by every raw storage backend."""
    return tuple(_SOURCE_EXTENSIONS)


def __getattr__(name: str):
    """Lazily preserve the former LocalRawArtifactStore import path."""
    if name == "LocalRawArtifactStore":
        from threatflow.local_raw_storage import LocalRawArtifactStore

        return LocalRawArtifactStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def create_raw_artifact_store(settings: Settings | None = None) -> RawArtifactStore:
    """Build the configured raw storage backend."""
    from threatflow.config import Settings

    settings = settings or Settings()
    if settings.raw_storage_backend == "local":
        from threatflow.local_raw_storage import LocalRawArtifactStore

        return LocalRawArtifactStore(settings.raw_data_dir)
    if settings.raw_storage_backend == "s3":
        from threatflow.s3_raw_storage import S3RawArtifactStore

        return S3RawArtifactStore(
            bucket=settings.s3_bronze_bucket or "",
            prefix=settings.s3_bronze_prefix,
            region_name=settings.aws_region,
            connect_timeout=settings.http_connect_timeout,
            read_timeout=settings.http_read_timeout,
            max_attempts=settings.http_retries + 1,
        )
    raise ValueError(f"unsupported raw storage backend: {settings.raw_storage_backend}")


def create_validated_replica_store(settings: Settings | None = None) -> RawArtifactStore | None:
    """Build the optional S3 target used only after source validation succeeds."""
    from threatflow.config import Settings

    settings = settings or Settings()
    if not settings.s3_replication_enabled:
        return None
    from threatflow.s3_raw_storage import S3RawArtifactStore

    return S3RawArtifactStore(
        bucket=settings.s3_bronze_bucket or "",
        prefix=settings.s3_bronze_prefix,
        region_name=settings.aws_region,
        connect_timeout=settings.http_connect_timeout,
        read_timeout=settings.http_read_timeout,
        max_attempts=settings.http_retries + 1,
    )


def replicate_validated_artifact(
    replica_store: RawArtifactStore | None,
    local_artifact: RawArtifactRef,
    content: bytes,
    acquired_at: datetime,
) -> RawArtifactRef | None:
    """Copy exact validated bytes to S3 and verify that logical identity is unchanged."""
    if replica_store is None:
        return None
    if local_artifact.backend != "local":
        raise ValueError("validated S3 replication requires a local source artifact")
    replica = replica_store.store(
        local_artifact.source,
        content,
        acquired_at,
        local_artifact.extension,
        content_type=local_artifact.content_type,
    )
    expected = (
        local_artifact.source,
        local_artifact.sha256,
        local_artifact.extension,
        local_artifact.size_bytes,
    )
    actual = (replica.source, replica.sha256, replica.extension, replica.size_bytes)
    if replica.backend != "s3" or actual != expected:
        raise ValueError("S3 replica identity does not match the validated local artifact")
    return replica


def store_raw_artifact(
    source: str,
    content: bytes,
    acquired_at: datetime,
    extension: str,
    *,
    raw_data_dir: str | Path | None = None,
) -> RawArtifactResult:
    """Compatibility wrapper around the local raw storage adapter."""
    from threatflow.config import Settings
    from threatflow.local_raw_storage import LocalRawArtifactStore

    root = Path(raw_data_dir) if raw_data_dir is not None else Path(Settings().raw_data_dir)
    return LocalRawArtifactStore(root).store(source, content, acquired_at, extension)
