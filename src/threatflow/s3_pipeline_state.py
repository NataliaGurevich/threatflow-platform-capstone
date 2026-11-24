"""Small S3-backed control state used by local Airflow ingestion."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, date, datetime
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.config import Settings


class S3PipelineState:
    """Read committed AWS state without reintroducing a local application database."""

    def __init__(
        self,
        *,
        bronze_bucket: str,
        silver_bucket: str,
        bronze_prefix: str = "bronze",
        silver_prefix: str = "silver",
        region_name: str | None = None,
        connect_timeout: float = 10,
        read_timeout: float = 60,
        max_attempts: int = 4,
        client: Any | None = None,
    ) -> None:
        if not bronze_bucket.strip() or not silver_bucket.strip():
            raise ValueError("Bronze and Silver buckets are required for AWS pipeline state")
        self.bronze_bucket = bronze_bucket
        self.silver_bucket = silver_bucket
        self.bronze_prefix = bronze_prefix.strip("/")
        self.silver_prefix = silver_prefix.strip("/")
        if not self.bronze_prefix or not self.silver_prefix:
            raise ValueError("Bronze and Silver prefixes must not be empty")
        self.client = client or boto3.client(
            "s3",
            region_name=region_name,
            config=Config(
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
                retries={"mode": "standard", "total_max_attempts": max_attempts},
            ),
        )

    @classmethod
    def from_settings(cls, settings: Settings) -> S3PipelineState:
        return cls(
            bronze_bucket=settings.s3_bronze_bucket or "",
            silver_bucket=settings.s3_silver_bucket or "",
            bronze_prefix=settings.s3_bronze_prefix,
            silver_prefix=settings.s3_silver_prefix,
            region_name=settings.aws_region,
            connect_timeout=settings.http_connect_timeout,
            read_timeout=settings.http_read_timeout,
            max_attempts=settings.http_retries + 1,
        )

    def nvd_covered_until(self) -> datetime | None:
        value, _ = self._get_json(self.bronze_bucket, self._nvd_checkpoint_key())
        if value is None:
            return None
        covered_until = _timestamp(value.get("covered_until"), "covered_until")
        if value.get("source") != "nvd" or value.get("mode") != "modified":
            raise ValueError("NVD checkpoint identity is invalid")
        return covered_until

    def advance_nvd_covered_until(self, covered_until: datetime) -> None:
        if covered_until.tzinfo is None or covered_until.utcoffset() is None:
            raise ValueError("covered_until must be timezone-aware")
        key = self._nvd_checkpoint_key()
        current, etag = self._get_json(self.bronze_bucket, key)
        if current is not None:
            if current.get("source") != "nvd" or current.get("mode") != "modified":
                raise ValueError("NVD checkpoint identity is invalid")
            previous = _timestamp(current.get("covered_until"), "covered_until")
            if previous >= covered_until:
                return
        payload = {
            "schema_version": 1,
            "source": "nvd",
            "mode": "modified",
            "covered_until": covered_until.astimezone(UTC).isoformat(),
            "updated_at": datetime.now(UTC).isoformat(),
        }
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        digest = hashlib.sha256(encoded).hexdigest()
        parameters: dict[str, Any] = {
            "Bucket": self.bronze_bucket,
            "Key": key,
            "Body": encoded,
            "ContentLength": len(encoded),
            "ContentType": "application/json",
            "ChecksumSHA256": _base64_sha256(digest),
            "Metadata": {"sha256": digest, "state-kind": "nvd-modified-checkpoint"},
            "ServerSideEncryption": "AES256",
        }
        if etag is None:
            parameters["IfNoneMatch"] = "*"
        else:
            parameters["IfMatch"] = etag
        self.client.put_object(**parameters)

    def latest_cisa_record_count(self) -> int | None:
        key = f"{self.silver_prefix}/cisa_kev_snapshots/_latest.json"
        value, _ = self._get_json(self.silver_bucket, key)
        if value is None:
            return None
        if value.get("dataset") != "cisa_kev_snapshots":
            raise ValueError("CISA latest pointer dataset is invalid")
        return _positive_count(value.get("record_count"), "CISA latest pointer")

    def epss_record_count(self, score_date: date) -> int | None:
        key = (
            f"{self.silver_prefix}/epss_scores/"
            f"score_date={score_date.isoformat()}/_manifest.json"
        )
        value, _ = self._get_json(self.silver_bucket, key)
        if value is None:
            return None
        if (
            value.get("dataset") != "epss_scores"
            or value.get("score_date") != score_date.isoformat()
        ):
            raise ValueError("EPSS Silver manifest identity is invalid")
        return _positive_count(value.get("record_count"), "EPSS Silver manifest")

    def _nvd_checkpoint_key(self) -> str:
        return f"{self.bronze_prefix}/_control/nvd/modified-checkpoint.json"

    def _get_json(self, bucket: str, key: str) -> tuple[dict[str, Any] | None, str | None]:
        try:
            response = self.client.get_object(
                Bucket=bucket,
                Key=key,
                ChecksumMode="ENABLED",
            )
        except ClientError as exc:
            if _is_not_found(exc):
                return None, None
            raise
        body = response["Body"]
        try:
            encoded = body.read()
        finally:
            body.close()
        try:
            value = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid JSON state object: s3://{bucket}/{key}") from exc
        if not isinstance(value, dict):
            raise ValueError(f"state object must contain a JSON object: s3://{bucket}/{key}")
        digest = hashlib.sha256(encoded).hexdigest()
        expected_checksum = _base64_sha256(digest)
        checksum = response.get("ChecksumSHA256")
        metadata_digest = response.get("Metadata", {}).get("sha256")
        if checksum is not None and checksum != expected_checksum:
            raise ValueError(f"state object checksum is invalid: s3://{bucket}/{key}")
        if metadata_digest is not None and metadata_digest != digest:
            raise ValueError(f"state object SHA-256 metadata is invalid: s3://{bucket}/{key}")
        return value, response.get("ETag")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)


def _positive_count(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} record_count is invalid")
    return value


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _is_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 404 or error.get("Code") in {"404", "NoSuchKey", "NotFound"}
