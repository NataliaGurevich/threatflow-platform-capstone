"""Amazon S3 implementation of immutable Bronze raw artifact storage."""

from __future__ import annotations

import base64
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


class RawArtifactIntegrityError(OSError):
    """Raised when stored S3 metadata or downloaded bytes do not match the artifact identity."""


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
    ) -> RawArtifactRef:
        """Create one immutable object or safely reuse its verified existing equivalent."""
        normalized_extension, resolved_content_type = validate_raw_artifact_input(
            source, content, acquired_at, extension, content_type
        )
        if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
            raise ValueError("acquired_at must be timezone-aware for S3 metadata")
        digest = calculate_sha256(content)
        checksum_sha256 = _base64_sha256(digest)
        object_key = self._object_key(source, digest, normalized_extension)
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
                Metadata={
                    "sha256": digest,
                    "source": source,
                    "acquired-at": acquired_at.astimezone(UTC).isoformat(),
                },
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
        self._verify_head(
            head,
            source=source,
            digest=digest,
            size_bytes=len(content),
            content_type=resolved_content_type,
            checksum_sha256=checksum_sha256,
        )

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
        )

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
        return f"{self.prefix}/source={source}/sha256={digest}.{extension}"

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
        if mismatches:
            raise RawArtifactIntegrityError(
                f"stored S3 object failed integrity verification: {', '.join(mismatches)}"
            )


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _is_precondition_failed(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 412 or error.get("Code") in {"412", "PreconditionFailed"}
