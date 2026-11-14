"""AWS Lambda adapter for independent EPSS Bronze-to-Silver processing."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.ingestion.epss_parser import extract_score_date
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.epss_silver import (
    DATASET_NAME,
    MANIFEST_FILE_NAME,
    PARQUET_FILE_NAME,
    EpssSilverResult,
    transform_epss_bytes,
)
from threatflow.transformation.pipeline_events import emit_pipeline_event

LOGGER = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class EpssSilverLambdaConfig:
    bronze_bucket: str
    silver_bucket: str
    bronze_prefix: str = "bronze"
    silver_prefix: str = "silver"
    aws_region: str | None = None
    temporary_root: str = "/tmp"

    def __post_init__(self) -> None:
        if not self.bronze_bucket.strip():
            raise ValueError("bronze_bucket must not be empty")
        if not self.silver_bucket.strip():
            raise ValueError("silver_bucket must not be empty")
        if not self.bronze_prefix.strip("/"):
            raise ValueError("bronze_prefix must not be empty")
        if not self.silver_prefix.strip("/"):
            raise ValueError("silver_prefix must not be empty")

    @classmethod
    def from_environment(cls) -> EpssSilverLambdaConfig:
        bronze_bucket = os.getenv("THREATFLOW_S3_BRONZE_BUCKET", "")
        silver_bucket = os.getenv("THREATFLOW_S3_SILVER_BUCKET", "")
        return cls(
            bronze_bucket=bronze_bucket,
            silver_bucket=silver_bucket,
            bronze_prefix=os.getenv("THREATFLOW_S3_BRONZE_PREFIX", "bronze"),
            silver_prefix=os.getenv("THREATFLOW_S3_SILVER_PREFIX", "silver"),
            aws_region=os.getenv("THREATFLOW_AWS_REGION"),
        )


@dataclass(frozen=True)
class BronzeObjectEvent:
    bucket: str
    key: str
    version_id: str
    size_bytes: int
    source_sha256: str

    @property
    def uri(self) -> str:
        return f"s3://{self.bucket}/{self.key}"


@dataclass(frozen=True)
class BronzeObject:
    event: BronzeObjectEvent
    content: bytes
    acquired_at: datetime


class EpssSilverS3Processor:
    """Validate one versioned EPSS Bronze object and commit its Silver partition."""

    def __init__(
        self,
        config: EpssSilverLambdaConfig,
        *,
        s3_client: Any,
    ) -> None:
        self.config = config
        self.s3 = s3_client

    def process(self, event: BronzeObjectEvent) -> EpssSilverResult:
        bronze = self._read_bronze(event)
        score_date = extract_score_date(bronze.content)
        committed = self._load_committed_partition(score_date, event.source_sha256)
        if committed is not None:
            return committed

        Path(self.config.temporary_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="threatflow-epss-silver-",
            dir=self.config.temporary_root,
        ) as temporary_root:
            local_result = transform_epss_bytes(
                bronze.content,
                score_date=score_date,
                source_sha256=event.source_sha256,
                source_uri=event.uri,
                source_version_id=event.version_id,
                acquired_at=bronze.acquired_at,
                expected_record_count=None,
                output_root=temporary_root,
            )
            return self._publish_partition(local_result)

    def _read_bronze(self, event: BronzeObjectEvent) -> BronzeObject:
        if event.bucket != self.config.bronze_bucket:
            raise ValueError(f"unexpected Bronze bucket: {event.bucket}")
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
        mismatches: list[str] = []
        if len(content) != event.size_bytes or response.get("ContentLength") != len(content):
            mismatches.append("ContentLength")
        if actual_sha256 != event.source_sha256:
            mismatches.append("SHA-256")
        if response.get("ChecksumSHA256") != _base64_sha256(actual_sha256):
            mismatches.append("ChecksumSHA256")
        if response.get("ContentType") != "application/gzip":
            mismatches.append("ContentType")
        if response.get("ServerSideEncryption") != "AES256":
            mismatches.append("ServerSideEncryption")
        if metadata.get("sha256") != event.source_sha256:
            mismatches.append("Metadata.sha256")
        if metadata.get("source") != "epss":
            mismatches.append("Metadata.source")
        if response.get("VersionId") != event.version_id:
            mismatches.append("VersionId")
        if mismatches:
            raise ValueError(
                "EPSS Bronze object failed integrity verification: " + ", ".join(mismatches)
            )

        acquired_at = _parse_acquired_at(metadata.get("acquired-at"))
        return BronzeObject(event=event, content=content, acquired_at=acquired_at)

    def _load_committed_partition(
        self,
        score_date: date,
        source_sha256: str,
    ) -> EpssSilverResult | None:
        parquet_key, manifest_key = self._partition_keys(score_date)
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
        try:
            manifest = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid EPSS Silver manifest: {manifest_key}") from exc
        manifest_metadata = response.get("Metadata", {})
        if (
            response.get("ChecksumSHA256") != _base64_sha256(calculate_sha256(encoded))
            or response.get("ContentType") != "application/json"
            or response.get("ServerSideEncryption") != "AES256"
            or manifest_metadata.get("source-sha256") != source_sha256
        ):
            raise ValueError(f"EPSS Silver manifest failed integrity verification: {manifest_key}")

        self._verify_manifest_identity(manifest, score_date, source_sha256)
        parquet = manifest.get("parquet", {})
        parquet_sha256 = parquet.get("sha256")
        parquet_size = parquet.get("size_bytes")
        record_count = manifest.get("record_count")
        if not _SHA256.fullmatch(parquet_sha256 or ""):
            raise ValueError("EPSS Silver manifest has an invalid Parquet SHA-256")
        if not isinstance(parquet_size, int) or parquet_size < 1:
            raise ValueError("EPSS Silver manifest has an invalid Parquet size")
        if not isinstance(record_count, int) or record_count < 1:
            raise ValueError("EPSS Silver manifest has an invalid record count")
        self._verify_silver_object(
            parquet_key,
            sha256=parquet_sha256,
            size_bytes=parquet_size,
            source_sha256=source_sha256,
        )
        return EpssSilverResult(
            dataset=DATASET_NAME,
            score_date=score_date,
            source_sha256=source_sha256,
            record_count=record_count,
            parquet_path=f"s3://{self.config.silver_bucket}/{parquet_key}",
            manifest_path=f"s3://{self.config.silver_bucket}/{manifest_key}",
            parquet_sha256=parquet_sha256,
            parquet_size_bytes=parquet_size,
            created=False,
        )

    def _publish_partition(self, local: EpssSilverResult) -> EpssSilverResult:
        parquet_key, manifest_key = self._partition_keys(local.score_date)
        parquet_path = Path(local.parquet_path)
        manifest_path = Path(local.manifest_path)
        self._put_immutable_file(
            key=parquet_key,
            path=parquet_path,
            content_type="application/vnd.apache.parquet",
            sha256=local.parquet_sha256,
            metadata={
                "dataset": DATASET_NAME,
                "score-date": local.score_date.isoformat(),
                "source-sha256": local.source_sha256,
                "record-count": str(local.record_count),
            },
        )
        manifest_bytes = manifest_path.read_bytes()
        manifest_sha256 = calculate_sha256(manifest_bytes)
        manifest_created = self._put_immutable_bytes(
            key=manifest_key,
            content=manifest_bytes,
            content_type="application/json",
            sha256=manifest_sha256,
            metadata={
                "dataset": DATASET_NAME,
                "score-date": local.score_date.isoformat(),
                "source-sha256": local.source_sha256,
            },
        )
        committed = self._load_committed_partition(local.score_date, local.source_sha256)
        if committed is None:
            raise RuntimeError("EPSS Silver manifest was not visible after publication")
        return EpssSilverResult(**{**asdict(committed), "created": manifest_created})

    def _put_immutable_file(
        self,
        *,
        key: str,
        path: Path,
        content_type: str,
        sha256: str,
        metadata: dict[str, str],
    ) -> bool:
        try:
            with path.open("rb") as body:
                self.s3.put_object(
                    Bucket=self.config.silver_bucket,
                    Key=key,
                    Body=body,
                    ContentLength=path.stat().st_size,
                    ContentType=content_type,
                    ChecksumSHA256=_base64_sha256(sha256),
                    Metadata=metadata,
                    ServerSideEncryption="AES256",
                    IfNoneMatch="*",
                )
            return True
        except ClientError as exc:
            if not _is_precondition_failed(exc):
                raise
            self._verify_silver_object(
                key,
                sha256=sha256,
                size_bytes=path.stat().st_size,
                source_sha256=metadata["source-sha256"],
            )
            return False

    def _put_immutable_bytes(
        self,
        *,
        key: str,
        content: bytes,
        content_type: str,
        sha256: str,
        metadata: dict[str, str],
    ) -> bool:
        try:
            self.s3.put_object(
                Bucket=self.config.silver_bucket,
                Key=key,
                Body=content,
                ContentLength=len(content),
                ContentType=content_type,
                ChecksumSHA256=_base64_sha256(sha256),
                Metadata=metadata,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            return True
        except ClientError as exc:
            if not _is_precondition_failed(exc):
                raise
            return False

    def _verify_silver_object(
        self,
        key: str,
        *,
        sha256: str,
        size_bytes: int,
        source_sha256: str,
    ) -> None:
        head = self.s3.head_object(
            Bucket=self.config.silver_bucket,
            Key=key,
            ChecksumMode="ENABLED",
        )
        metadata = head.get("Metadata", {})
        if (
            head.get("ContentLength") != size_bytes
            or head.get("ChecksumSHA256") != _base64_sha256(sha256)
            or head.get("ContentType") != "application/vnd.apache.parquet"
            or head.get("ServerSideEncryption") != "AES256"
            or metadata.get("source-sha256") != source_sha256
        ):
            raise FileExistsError(f"conflicting EPSS Silver object: {key}")

    def _verify_manifest_identity(
        self,
        manifest: dict[str, Any],
        score_date: date,
        source_sha256: str,
    ) -> None:
        source = manifest.get("source", {})
        expected = (DATASET_NAME, score_date.isoformat(), source_sha256)
        actual = (manifest.get("dataset"), manifest.get("score_date"), source.get("sha256"))
        if actual != expected:
            raise FileExistsError(
                f"conflicting EPSS Silver partition: score_date={score_date.isoformat()}"
            )

    def _partition_keys(self, score_date: date) -> tuple[str, str]:
        root = self.config.silver_prefix.strip("/")
        partition = f"{root}/{DATASET_NAME}/score_date={score_date.isoformat()}"
        return f"{partition}/{PARQUET_FILE_NAME}", f"{partition}/{MANIFEST_FILE_NAME}"


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process direct S3 notifications or S3 notifications wrapped by SQS."""
    del context
    processor = _environment_processor()
    records = event.get("Records")
    if not isinstance(records, list) or not records:
        raise ValueError("Lambda event must contain at least one record")
    if all(record.get("eventSource") == "aws:sqs" for record in records):
        failures: list[dict[str, str]] = []
        for record in records:
            message_id = record.get("messageId")
            try:
                if not isinstance(message_id, str) or not message_id:
                    raise ValueError("SQS record has no messageId")
                body = json.loads(record.get("body", ""))
                if _is_expected_s3_test_event(body, processor.config):
                    LOGGER.info(
                        "Ignoring S3 destination validation event: bucket=%s",
                        body["Bucket"],
                    )
                    continue
                process_s3_notification(body, processor)
            except Exception:
                LOGGER.exception("EPSS Silver SQS message failed: message_id=%s", message_id)
                failures.append({"itemIdentifier": message_id or "missing-message-id"})
        return {"batchItemFailures": failures}

    results = process_s3_notification(event, processor)
    return {
        "processed": len(results),
        "results": [_result_payload(result) for result in results],
    }


def process_s3_notification(
    event: dict[str, Any],
    processor: EpssSilverS3Processor,
) -> list[EpssSilverResult]:
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
            source="epss",
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
                source="epss",
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
            source="epss",
            source_sha256=bronze.source_sha256,
            bronze_bucket=bronze.bucket,
            bronze_key=bronze.key,
            bronze_version_id=bronze.version_id,
            duration_ms=round((time.monotonic() - started) * 1000),
            record_count=result.record_count,
            score_date=result.score_date.isoformat(),
            silver_uri=result.parquet_path,
        )
        results.append(result)
    return results


def _parse_s3_record(
    record: dict[str, Any],
    config: EpssSilverLambdaConfig,
) -> BronzeObjectEvent:
    if record.get("eventSource") != "aws:s3":
        raise ValueError("notification record is not an S3 event")
    if not str(record.get("eventName", "")).startswith("ObjectCreated:"):
        raise ValueError("S3 event is not an object-created notification")
    try:
        bucket = record["s3"]["bucket"]["name"]
        object_data = record["s3"]["object"]
        key = unquote_plus(object_data["key"])
        version_id = object_data["versionId"]
        size_bytes = object_data["size"]
    except (KeyError, TypeError) as exc:
        raise ValueError("S3 event is missing bucket, key, versionId, or size") from exc
    if bucket != config.bronze_bucket:
        raise ValueError(f"unexpected Bronze bucket: {bucket}")
    if not isinstance(version_id, str) or not version_id:
        raise ValueError("S3 event must identify an immutable object version")
    if not isinstance(size_bytes, int) or size_bytes < 1:
        raise ValueError("S3 event has an invalid object size")
    prefix = re.escape(config.bronze_prefix.strip("/"))
    match = re.fullmatch(
        rf"{prefix}/source=epss/sha256=([0-9a-f]{{64}})\.csv\.gz",
        key,
    )
    if match is None:
        raise ValueError(f"S3 object is not an EPSS Bronze artifact: {key}")
    return BronzeObjectEvent(
        bucket=bucket,
        key=key,
        version_id=version_id,
        size_bytes=size_bytes,
        source_sha256=match.group(1),
    )


def _is_expected_s3_test_event(
    event: dict[str, Any],
    config: EpssSilverLambdaConfig,
) -> bool:
    return (
        event.get("Service") == "Amazon S3"
        and event.get("Event") == "s3:TestEvent"
        and event.get("Bucket") == config.bronze_bucket
    )


@lru_cache(maxsize=1)
def _environment_processor() -> EpssSilverS3Processor:
    config = EpssSilverLambdaConfig.from_environment()
    client = boto3.client(
        "s3",
        region_name=config.aws_region,
        config=Config(
            connect_timeout=5,
            read_timeout=60,
            retries={"mode": "standard", "total_max_attempts": 4},
        ),
    )
    return EpssSilverS3Processor(config, s3_client=client)


def _parse_acquired_at(value: str | None) -> datetime:
    if not value:
        raise ValueError("EPSS Bronze object has no acquired-at metadata")
    try:
        acquired_at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("EPSS Bronze acquired-at metadata is invalid") from exc
    if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
        raise ValueError("EPSS Bronze acquired-at metadata must be timezone-aware")
    return acquired_at


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _is_not_found(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 404 or error.get("Code") in {"404", "NoSuchKey", "NotFound"}


def _is_precondition_failed(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 412 or error.get("Code") in {"412", "PreconditionFailed"}


def _result_payload(result: EpssSilverResult) -> dict[str, Any]:
    return {**asdict(result), "score_date": result.score_date.isoformat()}
