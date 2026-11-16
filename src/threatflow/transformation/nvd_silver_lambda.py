"""AWS Lambda adapter for committed NVD Bronze windows."""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.nvd_silver import (
    MANIFEST_FILE_NAME,
    PARQUET_FILE_NAME,
    NvdSilverPageInput,
    NvdSilverResult,
    transform_nvd_window,
)
from threatflow.transformation.nvd_window import parse_nvd_window_manifest
from threatflow.transformation.pipeline_events import emit_pipeline_event

LOGGER = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NvdSilverLambdaConfig:
    bronze_bucket: str
    silver_bucket: str
    bronze_prefix: str = "bronze"
    silver_prefix: str = "silver"
    aws_region: str | None = None
    temporary_root: str = "/tmp"

    def __post_init__(self) -> None:
        if not self.bronze_bucket.strip() or not self.silver_bucket.strip():
            raise ValueError("Bronze and Silver buckets must not be empty")

    @classmethod
    def from_environment(cls) -> NvdSilverLambdaConfig:
        return cls(
            bronze_bucket=os.getenv("THREATFLOW_S3_BRONZE_BUCKET", ""),
            silver_bucket=os.getenv("THREATFLOW_S3_SILVER_BUCKET", ""),
            bronze_prefix=os.getenv("THREATFLOW_S3_BRONZE_PREFIX", "bronze"),
            silver_prefix=os.getenv("THREATFLOW_S3_SILVER_PREFIX", "silver"),
            aws_region=os.getenv("THREATFLOW_AWS_REGION"),
        )


@dataclass(frozen=True)
class NvdBronzeWindowEvent:
    bucket: str
    key: str
    version_id: str
    size_bytes: int
    source_sha256: str


class NvdSilverS3Processor:
    def __init__(self, config: NvdSilverLambdaConfig, *, s3_client: Any) -> None:
        self.config = config
        self.s3 = s3_client

    def process(self, event: NvdBronzeWindowEvent) -> NvdSilverResult:
        window_content, window = self._read_window(event)
        pages = [NvdSilverPageInput(page, self._read_page(page)) for page in window.pages]
        committed = self._load_committed(event, window.mode)
        if committed is not None:
            return committed
        Path(self.config.temporary_root).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="threatflow-nvd-silver-", dir=self.config.temporary_root
        ) as root:
            local = transform_nvd_window(
                window_content,
                window_sha256=event.source_sha256,
                window_uri=f"s3://{event.bucket}/{event.key}",
                window_version_id=event.version_id,
                pages=pages,
                output_root=root,
            )
            partition = self._partition(event.source_sha256, window.mode, local.window_end)
            parquet_key = f"{partition}/{PARQUET_FILE_NAME}"
            manifest_key = f"{partition}/{MANIFEST_FILE_NAME}"
            self._put_file(
                parquet_key,
                Path(local.parquet_path),
                "application/vnd.apache.parquet",
                local.parquet_sha256,
                {
                    "dataset": local.dataset,
                    "window-sha256": event.source_sha256,
                    "request-mode": window.mode,
                    "record-count": str(local.record_count),
                },
            )
            manifest_content = Path(local.manifest_path).read_bytes()
            created = self._put_bytes(
                manifest_key,
                manifest_content,
                "application/json",
                calculate_sha256(manifest_content),
                {
                    "dataset": local.dataset,
                    "window-sha256": event.source_sha256,
                    "request-mode": window.mode,
                },
            )
            verified = self._load_committed(event, window.mode)
            if verified is None:
                raise RuntimeError("NVD Silver manifest was not visible after publication")
            return NvdSilverResult(**{**asdict(verified), "created": created})

    def _read_window(self, event: NvdBronzeWindowEvent):
        response = self.s3.get_object(
            Bucket=event.bucket,
            Key=event.key,
            VersionId=event.version_id,
            ChecksumMode="ENABLED",
        )
        content = _read_body(response)
        metadata = response.get("Metadata", {})
        digest = calculate_sha256(content)
        expected_prefix = f"{self.config.bronze_prefix.strip('/')}/source=nvd/"
        mismatches = []
        if event.bucket != self.config.bronze_bucket:
            mismatches.append("Bucket")
        if not event.key.startswith(expected_prefix) or not event.key.endswith(".window.json"):
            mismatches.append("Key")
        if response.get("VersionId") != event.version_id:
            mismatches.append("VersionId")
        if len(content) != event.size_bytes or response.get("ContentLength") != len(content):
            mismatches.append("ContentLength")
        if digest != event.source_sha256:
            mismatches.append("SHA-256")
        if response.get("ChecksumSHA256") != _checksum(digest):
            mismatches.append("ChecksumSHA256")
        if response.get("ContentType") != "application/json":
            mismatches.append("ContentType")
        if response.get("ServerSideEncryption") != "AES256":
            mismatches.append("ServerSideEncryption")
        if metadata.get("source") != "nvd" or metadata.get("sha256") != digest:
            mismatches.append("Metadata.identity")
        if metadata.get("artifact-kind") != "window-manifest":
            mismatches.append("Metadata.artifact-kind")
        if mismatches:
            raise ValueError(
                "NVD Bronze window failed integrity verification: " + ", ".join(mismatches)
            )
        window = parse_nvd_window_manifest(content)
        if metadata.get("request-mode") != window.mode:
            raise ValueError("NVD Bronze window request-mode metadata mismatch")
        return content, window

    def _read_page(self, page) -> bytes:
        expected_prefix = f"{self.config.bronze_prefix.strip('/')}/source=nvd/"
        if (
            page.backend != "s3"
            or page.bucket != self.config.bronze_bucket
            or not page.key
            or not page.key.startswith(expected_prefix)
            or not page.version_id
        ):
            raise ValueError("NVD Bronze page is outside the configured prefix")
        response = self.s3.get_object(
            Bucket=page.bucket,
            Key=page.key,
            VersionId=page.version_id,
            ChecksumMode="ENABLED",
        )
        content = _read_body(response)
        metadata = response.get("Metadata", {})
        digest = calculate_sha256(content)
        if (
            response.get("VersionId") != page.version_id
            or len(content) != page.size_bytes
            or response.get("ContentLength") != page.size_bytes
            or digest != page.sha256
            or response.get("ChecksumSHA256") != _checksum(digest)
            or response.get("ContentType") != "application/json"
            or response.get("ServerSideEncryption") != "AES256"
            or metadata.get("source") != "nvd"
            or metadata.get("sha256") != digest
        ):
            raise ValueError("NVD Bronze page failed integrity verification")
        return content

    def _partition(self, sha256: str, mode: str, window_end) -> str:
        timestamp = window_end.strftime("%Y-%m-%dT%H-%M-%SZ")
        return (
            f"{self.config.silver_prefix.strip('/')}/nvd_cve_windows/"
            f"mode={mode}/window_end={timestamp}/window_id={sha256}"
        )

    def _load_committed(self, event: NvdBronzeWindowEvent, mode: str):
        window = parse_nvd_window_manifest(
            self._get_exact(event.bucket, event.key, event.version_id)
        )
        partition = self._partition(event.source_sha256, mode, window.requested_end)
        manifest_key = f"{partition}/{MANIFEST_FILE_NAME}"
        parquet_key = f"{partition}/{PARQUET_FILE_NAME}"
        try:
            response = self.s3.get_object(
                Bucket=self.config.silver_bucket,
                Key=manifest_key,
                ChecksumMode="ENABLED",
            )
        except ClientError as exc:
            if _not_found(exc):
                return None
            raise
        content = _read_body(response)
        if response.get("ChecksumSHA256") != _checksum(calculate_sha256(content)):
            raise ValueError("NVD Silver manifest checksum is invalid")
        value = json.loads(content)
        identity = (
            value.get("dataset"),
            value.get("mode"),
            value.get("window_id"),
            value.get("source", {}).get("sha256"),
            value.get("source", {}).get("version_id"),
        )
        expected = (
            "nvd_cve_windows",
            mode,
            event.source_sha256,
            event.source_sha256,
            event.version_id,
        )
        if identity != expected:
            raise FileExistsError("conflicting NVD Silver manifest")
        parquet = value.get("parquet", {})
        head = self.s3.head_object(
            Bucket=self.config.silver_bucket, Key=parquet_key, ChecksumMode="ENABLED"
        )
        if (
            head.get("ContentLength") != parquet.get("size_bytes")
            or head.get("ChecksumSHA256") != _checksum(parquet.get("sha256", ""))
            or head.get("Metadata", {}).get("window-sha256") != event.source_sha256
        ):
            raise ValueError("NVD Silver Parquet failed integrity verification")
        return NvdSilverResult(
            "nvd_cve_windows",
            mode,
            event.source_sha256,
            window.requested_start,
            window.requested_end,
            value["record_count"],
            f"s3://{self.config.silver_bucket}/{parquet_key}",
            f"s3://{self.config.silver_bucket}/{manifest_key}",
            parquet["sha256"],
            parquet["size_bytes"],
            False,
        )

    def _get_exact(self, bucket: str, key: str, version_id: str) -> bytes:
        return _read_body(
            self.s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)
        )

    def _put_file(self, key, path, content_type, sha256, metadata):
        try:
            with path.open("rb") as body:
                self.s3.put_object(
                    Bucket=self.config.silver_bucket,
                    Key=key,
                    Body=body,
                    ContentLength=path.stat().st_size,
                    ContentType=content_type,
                    ChecksumSHA256=_checksum(sha256),
                    Metadata=metadata,
                    ServerSideEncryption="AES256",
                    IfNoneMatch="*",
                )
        except ClientError as exc:
            if not _precondition(exc):
                raise
            head = self.s3.head_object(
                Bucket=self.config.silver_bucket, Key=key, ChecksumMode="ENABLED"
            )
            if (
                head.get("ContentLength") != path.stat().st_size
                or head.get("ChecksumSHA256") != _checksum(sha256)
                or head.get("Metadata", {}).get("window-sha256")
                != metadata["window-sha256"]
            ):
                raise FileExistsError(f"conflicting NVD Silver object: {key}") from None

    def _put_bytes(self, key, content, content_type, sha256, metadata) -> bool:
        try:
            self.s3.put_object(
                Bucket=self.config.silver_bucket,
                Key=key,
                Body=content,
                ContentLength=len(content),
                ContentType=content_type,
                ChecksumSHA256=_checksum(sha256),
                Metadata=metadata,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            return True
        except ClientError as exc:
            if not _precondition(exc):
                raise
            return False


def process_s3_notification(event: dict[str, Any], processor: NvdSilverS3Processor):
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
            source="nvd",
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
                source="nvd",
                source_sha256=bronze.source_sha256,
                bronze_bucket=bronze.bucket,
                bronze_key=bronze.key,
                bronze_version_id=bronze.version_id,
                error_type=type(exc).__name__,
                duration_ms=round((time.monotonic() - started) * 1000),
            )
            raise
        emit_pipeline_event(
            LOGGER,
            event="silver_committed" if result.created else "silver_reused",
            source="nvd",
            source_sha256=bronze.source_sha256,
            bronze_bucket=bronze.bucket,
            bronze_key=bronze.key,
            bronze_version_id=bronze.version_id,
            mode=result.mode,
            window_start=result.window_start,
            window_end=result.window_end,
            record_count=result.record_count,
            duration_ms=round((time.monotonic() - started) * 1000),
        )
        results.append(result)
    return results


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    if _test_event(event):
        return {"status": "test_event_acknowledged"}
    records = event.get("Records")
    if isinstance(records, list) and records and records[0].get("eventSource") == "aws:sqs":
        failures = []
        processor = _environment_processor()
        for record in records:
            message_id = record.get("messageId", "")
            try:
                body = json.loads(record["body"])
                if _test_event(body):
                    continue
                process_s3_notification(body, processor)
            except Exception:
                LOGGER.exception("NVD SQS message processing failed")
                failures.append({"itemIdentifier": message_id})
        return {"batchItemFailures": failures}
    results = process_s3_notification(event, _environment_processor())
    return {"processed": len(results)}


@lru_cache(maxsize=1)
def _environment_processor() -> NvdSilverS3Processor:
    config = NvdSilverLambdaConfig.from_environment()
    client = boto3.client(
        "s3",
        region_name=config.aws_region,
        config=Config(retries={"mode": "standard", "total_max_attempts": 4}),
    )
    return NvdSilverS3Processor(config, s3_client=client)


def _parse_s3_record(record, config):
    try:
        bucket = record["s3"]["bucket"]["name"]
        key = unquote_plus(record["s3"]["object"]["key"])
        version_id = record["s3"]["object"]["versionId"]
        size = record["s3"]["object"]["size"]
    except (KeyError, TypeError) as exc:
        raise ValueError("S3 event is missing bucket, key, versionId, or size") from exc
    match = re.search(r"sha256=([0-9a-f]{64})\.window\.json$", key)
    if (
        bucket != config.bronze_bucket
        or not match
        or type(size) is not int
        or size < 1
        or not version_id
    ):
        raise ValueError("S3 event does not identify an allowed NVD window manifest")
    return NvdBronzeWindowEvent(bucket, key, version_id, size, match.group(1))


def _test_event(event):
    return (
        isinstance(event, dict)
        and event.get("Service") == "Amazon S3"
        and event.get("Event") == "s3:TestEvent"
        and event.get("Bucket") == os.getenv("THREATFLOW_S3_BRONZE_BUCKET", "")
    )


def _read_body(response):
    body = response["Body"]
    try:
        return body.read()
    finally:
        body.close()


def _checksum(hex_digest: str) -> str:
    if not _SHA256.fullmatch(hex_digest):
        return ""
    return base64.b64encode(bytes.fromhex(hex_digest)).decode()


def _not_found(exc):
    return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404


def _precondition(exc):
    return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 412
