"""AWS Lambda adapter for incremental CISA Bronze-to-Silver snapshots."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.cisa_silver import (
    CisaSilverResult,
    transform_cisa_bytes,
)
from threatflow.transformation.cisa_silver_publish import (
    CisaSilverPublishCandidate,
    CisaSilverS3Publisher,
    load_cisa_silver_publish_candidates,
)
from threatflow.transformation.pipeline_events import emit_pipeline_event

LOGGER = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class CisaSilverLambdaConfig:
    bronze_bucket: str
    silver_bucket: str
    bronze_prefix: str = "bronze"
    silver_prefix: str = "silver"
    minimum_record_count: int = 100
    minimum_previous_ratio: float = 0.8
    aws_region: str | None = None
    temporary_root: str = "/tmp"

    def __post_init__(self) -> None:
        if not self.bronze_bucket.strip() or not self.silver_bucket.strip():
            raise ValueError("Bronze and Silver buckets must not be empty")
        if self.minimum_record_count < 1:
            raise ValueError("minimum_record_count must be at least 1")
        if not 0 < self.minimum_previous_ratio <= 1:
            raise ValueError("minimum_previous_ratio must be in (0, 1]")

    @classmethod
    def from_environment(cls) -> CisaSilverLambdaConfig:
        return cls(
            bronze_bucket=os.getenv("THREATFLOW_S3_BRONZE_BUCKET", ""),
            silver_bucket=os.getenv("THREATFLOW_S3_SILVER_BUCKET", ""),
            bronze_prefix=os.getenv("THREATFLOW_S3_BRONZE_PREFIX", "bronze"),
            silver_prefix=os.getenv("THREATFLOW_S3_SILVER_PREFIX", "silver"),
            minimum_record_count=int(os.getenv("THREATFLOW_CISA_MINIMUM_RECORD_COUNT", "100")),
            minimum_previous_ratio=float(
                os.getenv("THREATFLOW_CISA_MINIMUM_PREVIOUS_RATIO", "0.8")
            ),
            aws_region=os.getenv("THREATFLOW_AWS_REGION"),
        )


@dataclass(frozen=True)
class CisaBronzeEvent:
    bucket: str
    key: str
    version_id: str
    size_bytes: int
    source_sha256: str


@dataclass(frozen=True)
class CisaBronzeObject:
    event: CisaBronzeEvent
    content: bytes
    acquired_at: datetime
    record_count: int


class CisaSilverS3Processor:
    def __init__(self, config: CisaSilverLambdaConfig, *, s3_client: Any) -> None:
        self.config = config
        self.s3 = s3_client
        self.publisher = CisaSilverS3Publisher(
            config.silver_bucket, config.silver_prefix, client=s3_client
        )

    def process(self, event: CisaBronzeEvent) -> CisaSilverResult:
        bronze = self._read_bronze(event)
        previous_count = self._load_latest_count()
        minimum = self.config.minimum_record_count
        if previous_count is not None:
            minimum = max(minimum, int(previous_count * self.config.minimum_previous_ratio))
        if bronze.record_count < minimum:
            raise ValueError(
                f"CISA catalog is implausibly small: {bronze.record_count}, minimum {minimum}"
            )

        committed = self._load_committed(event, bronze.record_count)
        if committed is not None:
            self._publish_latest_candidate(committed, bronze.acquired_at)
            return committed

        Path(self.config.temporary_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="threatflow-cisa-silver-", dir=self.config.temporary_root
        ) as temporary_root:
            local = transform_cisa_bytes(
                bronze.content,
                snapshot_kind="snapshot",
                source_sha256=event.source_sha256,
                source_uri=f"s3://{event.bucket}/{event.key}",
                source_version_id=event.version_id,
                acquired_at=bronze.acquired_at,
                expected_record_count=bronze.record_count,
                output_root=temporary_root,
            )
            candidate = load_cisa_silver_publish_candidates(temporary_root)[0]
            created, _, uris = self.publisher.publish(candidate)
            self._publish_latest(candidate, bronze.acquired_at)
            return CisaSilverResult(
                dataset=local.dataset,
                snapshot_kind="snapshot",
                snapshot_id=local.snapshot_id,
                source_sha256=local.source_sha256,
                record_count=local.record_count,
                parquet_path=uris[0],
                manifest_path=uris[1],
                parquet_sha256=local.parquet_sha256,
                parquet_size_bytes=local.parquet_size_bytes,
                created=created,
            )

    def _load_committed(
        self, event: CisaBronzeEvent, record_count: int
    ) -> CisaSilverResult | None:
        partition = (
            f"{self.config.silver_prefix.strip('/')}/cisa_kev_snapshots/"
            f"snapshot_kind=snapshot/snapshot_id={event.source_sha256}"
        )
        parquet_key = f"{partition}/cisa_kev.parquet"
        manifest_key = f"{partition}/_manifest.json"
        try:
            response = self.s3.get_object(
                Bucket=self.config.silver_bucket,
                Key=manifest_key,
                ChecksumMode="ENABLED",
            )
        except ClientError as exc:
            if _is_not_found(exc):
                return None
            raise
        body = response["Body"]
        try:
            encoded = body.read()
        finally:
            body.close()
        if response.get("ChecksumSHA256") != _base64_sha256(calculate_sha256(encoded)):
            raise ValueError("CISA Silver manifest checksum is invalid")
        manifest = json.loads(encoded)
        identity = (
            manifest.get("dataset"),
            manifest.get("snapshot", {}).get("kind"),
            manifest.get("snapshot", {}).get("id"),
            manifest.get("source", {}).get("sha256"),
            manifest.get("record_count"),
        )
        expected = (
            "cisa_kev_snapshots",
            "snapshot",
            event.source_sha256,
            event.source_sha256,
            record_count,
        )
        if identity != expected:
            raise FileExistsError(f"conflicting CISA Silver manifest: {manifest_key}")
        parquet = manifest.get("parquet", {})
        parquet_sha256 = parquet.get("sha256")
        parquet_size = parquet.get("size_bytes")
        if not _SHA256.fullmatch(parquet_sha256 or "") or not isinstance(parquet_size, int):
            raise ValueError("CISA Silver manifest Parquet metadata is invalid")
        head = self.s3.head_object(
            Bucket=self.config.silver_bucket,
            Key=parquet_key,
            ChecksumMode="ENABLED",
        )
        if (
            head.get("ContentLength") != parquet_size
            or head.get("ChecksumSHA256") != _base64_sha256(parquet_sha256)
            or head.get("ContentType") != "application/vnd.apache.parquet"
            or head.get("Metadata", {}).get("source-sha256") != event.source_sha256
        ):
            raise ValueError("CISA Silver Parquet failed integrity verification")
        return CisaSilverResult(
            "cisa_kev_snapshots",
            "snapshot",
            event.source_sha256,
            event.source_sha256,
            record_count,
            f"s3://{self.config.silver_bucket}/{parquet_key}",
            f"s3://{self.config.silver_bucket}/{manifest_key}",
            parquet_sha256,
            parquet_size,
            False,
        )

    def _read_bronze(self, event: CisaBronzeEvent) -> CisaBronzeObject:
        response = self.s3.get_object(
            Bucket=event.bucket,
            Key=event.key,
            VersionId=event.version_id,
            ChecksumMode="ENABLED",
        )
        body = response["Body"]
        try:
            content = body.read()
        finally:
            body.close()
        metadata = response.get("Metadata", {})
        actual_sha256 = calculate_sha256(content)
        mismatches = []
        if event.bucket != self.config.bronze_bucket:
            mismatches.append("Bucket")
        if response.get("VersionId") != event.version_id:
            mismatches.append("VersionId")
        if len(content) != event.size_bytes or response.get("ContentLength") != len(content):
            mismatches.append("ContentLength")
        if actual_sha256 != event.source_sha256:
            mismatches.append("SHA-256")
        if response.get("ChecksumSHA256") != _base64_sha256(actual_sha256):
            mismatches.append("ChecksumSHA256")
        if response.get("ContentType") != "application/json":
            mismatches.append("ContentType")
        if response.get("ServerSideEncryption") != "AES256":
            mismatches.append("ServerSideEncryption")
        if metadata.get("source") != "cisa_kev":
            mismatches.append("Metadata.source")
        if metadata.get("sha256") != event.source_sha256:
            mismatches.append("Metadata.sha256")
        if metadata.get("request-mode") != "snapshot":
            mismatches.append("Metadata.request-mode")
        if mismatches:
            raise ValueError(
                "CISA Bronze object failed integrity verification: " + ", ".join(mismatches)
            )
        acquired_at = _parse_datetime(metadata.get("acquired-at"), "acquired-at")
        try:
            record_count = int(metadata.get("record-count", ""))
        except ValueError as exc:
            raise ValueError("CISA Bronze record-count metadata is invalid") from exc
        if record_count < 1:
            raise ValueError("CISA Bronze record-count metadata is invalid")
        return CisaBronzeObject(event, content, acquired_at, record_count)

    def _latest_key(self) -> str:
        return f"{self.config.silver_prefix.strip('/')}/cisa_kev_snapshots/_latest.json"

    def _load_latest_count(self) -> int | None:
        try:
            response = self.s3.get_object(
                Bucket=self.config.silver_bucket,
                Key=self._latest_key(),
                ChecksumMode="ENABLED",
            )
        except ClientError as exc:
            if _is_not_found(exc):
                return None
            raise
        body = response["Body"]
        try:
            encoded = body.read()
        finally:
            body.close()
        if response.get("ChecksumSHA256") != _base64_sha256(calculate_sha256(encoded)):
            raise ValueError("CISA latest pointer checksum is invalid")
        value = json.loads(encoded)
        count = value.get("record_count")
        if not isinstance(count, int) or count < 1:
            raise ValueError("CISA latest pointer record count is invalid")
        return count

    def _publish_latest(
        self, candidate: CisaSilverPublishCandidate, acquired_at: datetime
    ) -> None:
        payload = {
            "dataset": "cisa_kev_snapshots",
            "snapshot_kind": "snapshot",
            "snapshot_id": candidate.snapshot_id,
            "source_sha256": candidate.source_sha256,
            "record_count": candidate.record_count,
            "acquired_at": acquired_at.astimezone(UTC).isoformat(),
        }
        encoded = (json.dumps(payload, sort_keys=True) + "\n").encode()
        key = self._latest_key()
        try:
            current = self.s3.get_object(Bucket=self.config.silver_bucket, Key=key)
        except ClientError as exc:
            if not _is_not_found(exc):
                raise
            current = None
        parameters: dict[str, Any] = {
            "Bucket": self.config.silver_bucket,
            "Key": key,
            "Body": encoded,
            "ContentLength": len(encoded),
            "ContentType": "application/json",
            "ChecksumSHA256": _base64_sha256(calculate_sha256(encoded)),
            "Metadata": {"dataset": "cisa_kev_snapshots"},
            "ServerSideEncryption": "AES256",
        }
        if current is None:
            parameters["IfNoneMatch"] = "*"
        else:
            body = current["Body"]
            try:
                existing = json.loads(body.read())
            finally:
                body.close()
            existing_at = _parse_datetime(existing.get("acquired_at"), "latest acquired_at")
            if existing_at > acquired_at:
                return
            if (
                existing_at == acquired_at
                and existing.get("source_sha256") == candidate.source_sha256
            ):
                return
            parameters["IfMatch"] = current["ETag"]
        self.s3.put_object(**parameters)

    def _publish_latest_candidate(
        self, result: CisaSilverResult, acquired_at: datetime
    ) -> None:
        self._publish_latest(
            CisaSilverPublishCandidate(
                "snapshot",
                result.snapshot_id,
                result.source_sha256,
                result.record_count,
                Path("unused"),
                Path("unused"),
                result.parquet_sha256,
                result.parquet_size_bytes,
            ),
            acquired_at,
        )


def process_s3_notification(
    event: dict[str, Any], processor: CisaSilverS3Processor
) -> list[CisaSilverResult]:
    records = event.get("Records")
    if not isinstance(records, list) or not records:
        raise ValueError("S3 notification must contain at least one record")
    results = []
    for record in records:
        bronze = _parse_s3_record(record, processor.config)
        started = time.monotonic()
        emit_pipeline_event(
            LOGGER,
            event="bronze_received",
            source="cisa_kev",
            source_sha256=bronze.source_sha256,
            bronze_bucket=bronze.bucket,
            bronze_key=bronze.key,
            bronze_version_id=bronze.version_id,
            bronze_size_bytes=bronze.size_bytes,
        )
        try:
            result = processor.process(bronze)
        except Exception as exc:
            emit_pipeline_event(
                LOGGER,
                event="processing_failed",
                source="cisa_kev",
                source_sha256=bronze.source_sha256,
                bronze_bucket=bronze.bucket,
                bronze_key=bronze.key,
                bronze_version_id=bronze.version_id,
                duration_ms=round((time.monotonic() - started) * 1000),
                error_type=type(exc).__name__,
                error=str(exc),
            )
            raise
        emit_pipeline_event(
            LOGGER,
            event="silver_committed" if result.created else "silver_reused",
            source="cisa_kev",
            source_sha256=bronze.source_sha256,
            bronze_bucket=bronze.bucket,
            bronze_key=bronze.key,
            bronze_version_id=bronze.version_id,
            duration_ms=round((time.monotonic() - started) * 1000),
            record_count=result.record_count,
            silver_uri=result.parquet_path,
        )
        results.append(result)
    return results


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    processor = _environment_processor()
    records = event.get("Records")
    if not isinstance(records, list) or not records:
        raise ValueError("Lambda event must contain at least one record")
    if all(record.get("eventSource") == "aws:sqs" for record in records):
        failures = []
        for record in records:
            message_id = record.get("messageId")
            try:
                body = json.loads(record.get("body", ""))
                if _is_test_event(body, processor.config):
                    continue
                process_s3_notification(body, processor)
            except Exception:
                LOGGER.exception("CISA Silver SQS message failed: %s", message_id)
                failures.append({"itemIdentifier": message_id or "missing-message-id"})
        return {"batchItemFailures": failures}
    results = process_s3_notification(event, processor)
    return {"processed": len(results), "results": [asdict(result) for result in results]}


def _parse_s3_record(record: dict[str, Any], config: CisaSilverLambdaConfig) -> CisaBronzeEvent:
    if record.get("eventSource") != "aws:s3" or not str(
        record.get("eventName", "")
    ).startswith("ObjectCreated:"):
        raise ValueError("notification record is not an S3 object-created event")
    try:
        bucket = record["s3"]["bucket"]["name"]
        item = record["s3"]["object"]
        key = unquote_plus(item["key"])
        version_id = item["versionId"]
        size_bytes = item["size"]
    except (KeyError, TypeError) as exc:
        raise ValueError("S3 event is missing bucket, key, versionId, or size") from exc
    prefix = re.escape(config.bronze_prefix.strip("/"))
    match = re.fullmatch(
        rf"{prefix}/source=cisa_kev/sha256=([0-9a-f]{{64}})\.json", key
    )
    if bucket != config.bronze_bucket or match is None:
        raise ValueError("S3 object is not a configured CISA Bronze artifact")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError("S3 event must identify an immutable object version")
    if not isinstance(size_bytes, int) or size_bytes < 1:
        raise ValueError("S3 event has an invalid object size")
    return CisaBronzeEvent(bucket, key, version_id, size_bytes, match.group(1))


def _parse_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"CISA {label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"CISA {label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"CISA {label} must be timezone-aware")
    return parsed


def _base64_sha256(digest: str) -> str:
    return base64.b64encode(bytes.fromhex(digest)).decode("ascii")


def _is_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 404 or error.get("Code") in {"404", "NoSuchKey", "NotFound"}


def _is_test_event(event: dict[str, Any], config: CisaSilverLambdaConfig) -> bool:
    return (
        event.get("Service") == "Amazon S3"
        and event.get("Event") == "s3:TestEvent"
        and event.get("Bucket") == config.bronze_bucket
    )


@lru_cache(maxsize=1)
def _environment_processor() -> CisaSilverS3Processor:
    config = CisaSilverLambdaConfig.from_environment()
    client = boto3.client(
        "s3",
        region_name=config.aws_region,
        config=Config(
            connect_timeout=5,
            read_timeout=60,
            retries={"mode": "standard", "total_max_attempts": 4},
        ),
    )
    return CisaSilverS3Processor(config, s3_client=client)
