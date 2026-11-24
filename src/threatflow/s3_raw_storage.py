"""Amazon S3 implementation of immutable Bronze raw artifact storage."""

from __future__ import annotations

import base64
import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.raw_storage import (
    RawArtifactRef,
    calculate_sha256,
    validate_raw_artifact_input,
)

LOGGER = logging.getLogger(__name__)


class RawArtifactIntegrityError(OSError):
    """Raised when stored S3 metadata or downloaded bytes do not match the artifact identity."""


def build_s3_object_key(prefix: str, source: str, digest: str, extension: str) -> str:
    """Return the deterministic Bronze key without creating an AWS client."""
    normalized_prefix = prefix.strip("/")
    if not normalized_prefix:
        raise ValueError("prefix must contain at least one non-slash character")
    return f"{normalized_prefix}/source={source}/sha256={digest}.{extension}"


class S3RawArtifactStore:
    """Store exact raw bytes as immutable, content-addressed S3 objects."""

    backend = "s3"

    def __init__(
        self,
        bucket: str,
        prefix: str = "bronze",
        *,
        region_name: str | None = None,
        connect_timeout: float = 10,
        read_timeout: float = 60,
        max_attempts: int = 4,
        client: Any | None = None,
    ):
        if not bucket or not bucket.strip():
            raise ValueError("bucket must not be empty")
        normalized_prefix = prefix.strip("/")
        if not normalized_prefix:
            raise ValueError("prefix must contain at least one non-slash character")
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")

        self.bucket = bucket
        self.prefix = normalized_prefix
        self.client = client or boto3.client(
            "s3",
            region_name=region_name,
            config=Config(
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                retries={"mode": "standard", "total_max_attempts": max_attempts},
            ),
        )

    def store(
        self,
        source: str,
        content: bytes,
        acquired_at: datetime,
        extension: str,
        *,
        content_type: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> RawArtifactRef:
        """Create one immutable object or safely reuse its verified existing equivalent."""
        normalized_extension, resolved_content_type = validate_raw_artifact_input(
            source, content, acquired_at, extension, content_type
        )
        if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
            raise ValueError("acquired_at must be timezone-aware for S3 metadata")
        digest = calculate_sha256(content)
        extra_metadata = _validate_extra_metadata(metadata)
        checksum_sha256 = _base64_sha256(digest)
        object_key = self._object_key(source, digest, normalized_extension)
        requested_metadata = {
            "sha256": digest,
            "source": source,
            "acquired-at": acquired_at.astimezone(UTC).isoformat(),
            **extra_metadata,
        }
        created = False
        version_id: str | None = None

        try:
            response = self.client.put_object(
                Bucket=self.bucket,
                Key=object_key,
                Body=content,
                ContentLength=len(content),
                ContentType=resolved_content_type,
                ChecksumSHA256=checksum_sha256,
                Metadata=requested_metadata,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            created = True
            version_id = response.get("VersionId")
        except ClientError as exc:
            if not _is_precondition_failed(exc):
                raise

        head_parameters: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": object_key,
            "ChecksumMode": "ENABLED",
        }
        if version_id is not None:
            head_parameters["VersionId"] = version_id
        head = self.client.head_object(**head_parameters)
        if not created:
            self._verify_head(
                head,
                source=source,
                digest=digest,
                size_bytes=len(content),
                content_type=resolved_content_type,
                checksum_sha256=checksum_sha256,
                extra_metadata={},
            )
            missing_metadata = _missing_extra_metadata(head, extra_metadata)
            conflicting_metadata = _conflicting_extra_metadata(head, extra_metadata)
            if conflicting_metadata:
                self._verify_head(
                    head,
                    source=source,
                    digest=digest,
                    size_bytes=len(content),
                    content_type=resolved_content_type,
                    checksum_sha256=checksum_sha256,
                    extra_metadata=extra_metadata,
                )
            if missing_metadata:
                head, version_id = self._repair_missing_metadata(
                    head,
                    object_key=object_key,
                    source=source,
                    digest=digest,
                    content_type=resolved_content_type,
                    extra_metadata=extra_metadata,
                )
                created = True
        self._verify_head(
            head,
            source=source,
            digest=digest,
            size_bytes=len(content),
            content_type=resolved_content_type,
            checksum_sha256=checksum_sha256,
            extra_metadata=extra_metadata,
        )
        stored_acquired_at = _stored_acquired_at(head)

        return RawArtifactRef(
            source=source,
            sha256=digest,
            uri=f"s3://{self.bucket}/{object_key}",
            extension=normalized_extension,
            content_type=resolved_content_type,
            size_bytes=len(content),
            created=created,
            backend=self.backend,
            bucket=self.bucket,
            object_key=object_key,
            version_id=version_id or head.get("VersionId"),
            first_acquired_at=stored_acquired_at,
        )

    def _repair_missing_metadata(
        self,
        head: dict[str, Any],
        *,
        object_key: str,
        source: str,
        digest: str,
        content_type: str,
        extra_metadata: Mapping[str, str],
    ) -> tuple[dict[str, Any], str]:
        """Create a verified new version when a legacy object lacks routing metadata."""
        previous_version_id = head.get("VersionId")
        etag = head.get("ETag")
        if not isinstance(previous_version_id, str) or not previous_version_id:
            raise RawArtifactIntegrityError(
                "cannot repair S3 metadata without a source object VersionId"
            )
        if not isinstance(etag, str) or not etag:
            raise RawArtifactIntegrityError(
                "cannot repair S3 metadata without a source object ETag"
            )

        existing_metadata = head.get("Metadata", {})
        repaired_metadata = {
            **existing_metadata,
            "sha256": digest,
            "source": source,
            "acquired-at": existing_metadata["acquired-at"],
            **extra_metadata,
        }
        response = self.client.copy_object(
            Bucket=self.bucket,
            Key=object_key,
            CopySource={
                "Bucket": self.bucket,
                "Key": object_key,
                "VersionId": previous_version_id,
            },
            CopySourceIfMatch=etag,
            Metadata=repaired_metadata,
            MetadataDirective="REPLACE",
            ContentType=content_type,
            ChecksumAlgorithm="SHA256",
            ServerSideEncryption="AES256",
        )
        repaired_version_id = response.get("VersionId")
        if not isinstance(repaired_version_id, str) or not repaired_version_id:
            raise RawArtifactIntegrityError(
                "S3 metadata repair did not create a versioned object"
            )

        LOGGER.info(
            "stage=s3_raw_metadata_repaired source=%s sha256=%s "
            "previous_version_id=%s repaired_version_id=%s",
            source,
            digest,
            previous_version_id,
            repaired_version_id,
        )
        repaired_head = self.client.head_object(
            Bucket=self.bucket,
            Key=object_key,
            ChecksumMode="ENABLED",
            VersionId=repaired_version_id,
        )
        return repaired_head, repaired_version_id

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        """Read, close, and integrity-check an S3 artifact body."""
        locator = artifact.uri if isinstance(artifact, RawArtifactRef) else artifact
        bucket, object_key = self._parse_uri(locator)
        parameters: dict[str, Any] = {"Bucket": bucket, "Key": object_key}
        if isinstance(artifact, RawArtifactRef):
            if artifact.backend != self.backend:
                raise ValueError(f"cannot read {artifact.backend!r} artifact with S3 backend")
            if artifact.bucket is not None and artifact.bucket != bucket:
                raise ValueError("artifact bucket does not match its URI")
            if artifact.object_key is not None and artifact.object_key != object_key:
                raise ValueError("artifact object key does not match its URI")
            if artifact.version_id is not None:
                parameters["VersionId"] = artifact.version_id

        response = self.client.get_object(**parameters)
        body = response["Body"]
        try:
            content = body.read()
        finally:
            body.close()

        if isinstance(artifact, RawArtifactRef):
            if len(content) != artifact.size_bytes:
                raise RawArtifactIntegrityError(
                    f"downloaded size does not match manifest for {artifact.uri}"
                )
            if calculate_sha256(content) != artifact.sha256:
                raise RawArtifactIntegrityError(
                    f"downloaded SHA-256 does not match manifest for {artifact.uri}"
                )
        return content

    def _object_key(self, source: str, digest: str, extension: str) -> str:
        return build_s3_object_key(self.prefix, source, digest, extension)

    def _parse_uri(self, locator: str) -> tuple[str, str]:
        parsed = urlsplit(locator)
        object_key = parsed.path.removeprefix("/")
        if (
            parsed.scheme != "s3"
            or parsed.query
            or parsed.fragment
            or not parsed.netloc
            or not object_key
        ):
            raise ValueError(f"invalid S3 artifact URI: {locator}")
        if parsed.netloc != self.bucket:
            raise ValueError(f"artifact bucket {parsed.netloc!r} is not configured bucket")
        if not object_key.startswith(f"{self.prefix}/"):
            raise ValueError(f"artifact key is outside configured prefix {self.prefix!r}")
        return parsed.netloc, object_key

    @staticmethod
    def _verify_head(
        head: dict[str, Any],
        *,
        source: str,
        digest: str,
        size_bytes: int,
        content_type: str,
        checksum_sha256: str,
        extra_metadata: Mapping[str, str],
    ) -> None:
        metadata = head.get("Metadata", {})
        mismatches = []
        if head.get("ContentLength") != size_bytes:
            mismatches.append("ContentLength")
        if head.get("ChecksumSHA256") != checksum_sha256:
            mismatches.append("ChecksumSHA256")
        if head.get("ContentType") != content_type:
            mismatches.append("ContentType")
        if head.get("ServerSideEncryption") != "AES256":
            mismatches.append("ServerSideEncryption")
        if metadata.get("sha256") != digest:
            mismatches.append("Metadata.sha256")
        if metadata.get("source") != source:
            mismatches.append("Metadata.source")
        if not metadata.get("acquired-at"):
            mismatches.append("Metadata.acquired-at")
        for name, value in extra_metadata.items():
            if metadata.get(name) != value:
                mismatches.append(f"Metadata.{name}")
        if mismatches:
            raise RawArtifactIntegrityError(
                f"stored S3 object failed integrity verification: {', '.join(mismatches)}"
            )


def _validate_extra_metadata(metadata: Mapping[str, str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in (metadata or {}).items():
        normalized = name.strip().lower()
        if normalized in {"sha256", "source", "acquired-at"}:
            raise ValueError(f"reserved S3 Raw metadata key: {normalized}")
        if not normalized or not isinstance(value, str) or not value.strip():
            raise ValueError("S3 Raw metadata keys and values must not be empty")
        result[normalized] = value
    return result


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _stored_acquired_at(head: Mapping[str, Any]) -> datetime:
    value = head.get("Metadata", {}).get("acquired-at")
    if not isinstance(value, str):
        raise RawArtifactIntegrityError("stored S3 object has invalid acquired-at metadata")
    try:
        acquired_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RawArtifactIntegrityError(
            "stored S3 object has invalid acquired-at metadata"
        ) from exc
    if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
        raise RawArtifactIntegrityError("stored S3 object has invalid acquired-at metadata")
    return acquired_at.astimezone(UTC)


def _is_precondition_failed(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 412 or error.get("Code") in {"412", "PreconditionFailed"}


def _missing_extra_metadata(
    head: Mapping[str, Any], extra_metadata: Mapping[str, str]
) -> tuple[str, ...]:
    stored_metadata = head.get("Metadata", {})
    return tuple(name for name in extra_metadata if name not in stored_metadata)


def _conflicting_extra_metadata(
    head: Mapping[str, Any], extra_metadata: Mapping[str, str]
) -> tuple[str, ...]:
    stored_metadata = head.get("Metadata", {})
    return tuple(
        name
        for name, value in extra_metadata.items()
        if name in stored_metadata and stored_metadata[name] != value
    )
