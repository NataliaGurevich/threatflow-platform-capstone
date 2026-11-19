"""Manifest-last S3 publication for vulnerability-priority Gold."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from typing import Any

from botocore.exceptions import ClientError
from pyspark.sql import DataFrame

from threatflow.gold.local_publish import (
    DETAIL_DATASET,
    MANIFEST_VERSION,
    PARQUET_COMPRESSION,
    PRODUCT_NAME,
    SUMMARY_DATASET,
    GoldPublishConflict,
    GoldPublishError,
)
from threatflow.gold.quality import GoldQualityReport, validate_vulnerability_priority_gold
from threatflow.gold.vulnerability_priority import GOLD_SCHEMA_VERSION, POLICY_VERSION


@dataclass(frozen=True)
class S3GoldPublishResult:
    status: str
    snapshot_date: date
    input_fingerprint: str
    detail_uri: str
    summary_uri: str
    product_commit_uri: str
    quality: GoldQualityReport


class S3GoldPublisher:
    def __init__(self, bucket: str, prefix: str = "gold", *, s3_client: Any) -> None:
        if not bucket.strip() or not prefix.strip("/"):
            raise ValueError("Gold bucket and prefix must not be empty")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.s3 = s3_client

    def publish(
        self,
        detail: DataFrame,
        summary: DataFrame,
        *,
        input_plan: dict[str, Any],
        snapshot_date: date,
        source_cutoff: datetime,
        generated_at: datetime,
        input_fingerprint: str,
        snapshot_type: str,
        nvd_history_complete: bool,
        policy_version: str = POLICY_VERSION,
    ) -> S3GoldPublishResult:
        quality = validate_vulnerability_priority_gold(detail, summary)
        date_path = f"snapshot_date={snapshot_date.isoformat()}"
        run_path = f"run_id={input_fingerprint}"
        detail_prefix = f"{self.prefix}/{DETAIL_DATASET}/{date_path}/{run_path}"
        summary_prefix = f"{self.prefix}/{SUMMARY_DATASET}/{date_path}/{run_path}"
        commit_key = f"{self.prefix}/_commits/{PRODUCT_NAME}/{date_path}/_manifest.json"
        reused = self._reuse_commit(commit_key, input_fingerprint)
        if reused is not None:
            return S3GoldPublishResult(
                "REUSED",
                snapshot_date,
                input_fingerprint,
                self._uri(detail_prefix),
                self._uri(summary_prefix),
                self._uri(commit_key),
                reused,
            )

        detail_readback = self._ensure_parquet(detail, detail_prefix)
        summary_readback = self._ensure_parquet(summary, summary_prefix)
        if validate_vulnerability_priority_gold(detail_readback, summary_readback) != quality:
            raise GoldPublishError("S3 Parquet readback quality does not match source frames")
        detail_files = self._inventory(detail_prefix, detail.sparkSession)
        summary_files = self._inventory(summary_prefix, summary.sparkSession)
        common = {
            "manifest_version": MANIFEST_VERSION,
            "schema_version": GOLD_SCHEMA_VERSION,
            "policy_version": policy_version,
            "snapshot_date": snapshot_date.isoformat(),
            "snapshot_type": snapshot_type,
            "nvd_history_complete": nvd_history_complete,
            "source_cutoff": _utc_text(source_cutoff),
            "input_fingerprint": input_fingerprint,
            "inputs": input_plan,
            "generated_at": _utc_text(generated_at),
        }
        detail_manifest = {
            **common,
            "dataset": DETAIL_DATASET,
            "record_count": quality.detail_count,
            "tier_counts": quality.tier_counts,
            "parquet": {"compression": PARQUET_COMPRESSION, "files": detail_files},
        }
        summary_manifest = {
            **common,
            "dataset": SUMMARY_DATASET,
            "record_count": quality.summary_count,
            "detail_record_count": quality.detail_count,
            "tier_counts": quality.tier_counts,
            "parquet": {"compression": PARQUET_COMPRESSION, "files": summary_files},
        }
        detail_manifest_key = f"{detail_prefix}/_manifest.json"
        summary_manifest_key = f"{summary_prefix}/_manifest.json"
        detail_manifest_sha = self._put_json_immutable(detail_manifest_key, detail_manifest)
        summary_manifest_sha = self._put_json_immutable(summary_manifest_key, summary_manifest)
        commit = {
            "product": PRODUCT_NAME,
            "manifest_version": MANIFEST_VERSION,
            "gold_schema_version": GOLD_SCHEMA_VERSION,
            "policy_version": policy_version,
            "snapshot_date": snapshot_date.isoformat(),
            "snapshot_type": snapshot_type,
            "nvd_history_complete": nvd_history_complete,
            "source_cutoff": _utc_text(source_cutoff),
            "input_fingerprint": input_fingerprint,
            "status": "COMMITTED",
            "detail": {"key": detail_manifest_key, "sha256": detail_manifest_sha},
            "summary": {"key": summary_manifest_key, "sha256": summary_manifest_sha},
            "quality": asdict(quality),
            "generated_at": _utc_text(generated_at),
            "committed_at": _utc_text(datetime.now(UTC)),
        }
        self._put_json_immutable(commit_key, commit)
        return S3GoldPublishResult(
            "CREATED",
            snapshot_date,
            input_fingerprint,
            self._uri(detail_prefix),
            self._uri(summary_prefix),
            self._uri(commit_key),
            quality,
        )

    def _ensure_parquet(self, frame: DataFrame, prefix: str) -> DataFrame:
        uri = self._uri(prefix)
        if self._part_keys(prefix):
            return frame.sparkSession.read.parquet(uri)
        frame.write.mode("errorifexists").option(
            "compression", PARQUET_COMPRESSION
        ).parquet(uri)
        return frame.sparkSession.read.parquet(uri)

    def _inventory(self, prefix: str, spark: Any) -> list[dict[str, Any]]:
        result = []
        for key in self._part_keys(prefix):
            digest = hashlib.sha256()
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            body = response["Body"]
            try:
                while chunk := body.read(1024 * 1024):
                    digest.update(chunk)
            finally:
                body.close()
            result.append(
                {
                    "file": key.rsplit("/", 1)[1],
                    "sha256": digest.hexdigest(),
                    "size_bytes": response["ContentLength"],
                    "record_count": spark.read.parquet(self._uri(key)).count(),
                }
            )
        if not result:
            raise GoldPublishError(f"no Parquet part files in {self._uri(prefix)}")
        return result

    def _part_keys(self, prefix: str) -> list[str]:
        keys = []
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=f"{prefix}/"):
            for item in page.get("Contents", []):
                key = item.get("Key", "")
                if key.rsplit("/", 1)[-1].startswith("part-") and key.endswith(".parquet"):
                    keys.append(key)
        return sorted(keys)

    def _reuse_commit(self, key: str, fingerprint: str) -> GoldQualityReport | None:
        try:
            commit = self._get_json(key)
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 404 or exc.response.get("Error", {}).get("Code") in {
                "NoSuchKey",
                "404",
            }:
                return None
            raise
        if commit.get("input_fingerprint") != fingerprint:
            raise GoldPublishConflict(
                f"snapshot is committed with fingerprint {commit.get('input_fingerprint')}"
            )
        if commit.get("status") != "COMMITTED":
            raise GoldPublishError(f"invalid Gold commit status: {self._uri(key)}")
        quality = commit.get("quality", {})
        return GoldQualityReport(
            detail_count=int(quality["detail_count"]),
            summary_count=int(quality["summary_count"]),
            tier_counts={str(k): int(v) for k, v in quality["tier_counts"].items()},
        )

    def _get_json(self, key: str) -> dict[str, Any]:
        response = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"]
        try:
            value = json.loads(body.read())
        finally:
            body.close()
        if not isinstance(value, dict):
            raise GoldPublishError(f"invalid JSON object: {self._uri(key)}")
        return value

    def _put_json_immutable(self, key: str, value: dict[str, Any]) -> str:
        content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        sha256 = hashlib.sha256(content).hexdigest()
        try:
            self.s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                ContentLength=len(content),
                ContentType="application/json",
                ChecksumSHA256=base64.b64encode(bytes.fromhex(sha256)).decode(),
                Metadata={"sha256": sha256},
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
        except ClientError as exc:
            if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 412:
                raise
            existing = self._get_json(key)
            if existing != value:
                raise GoldPublishConflict(
                    f"conflicting immutable object: {self._uri(key)}"
                ) from exc
        return sha256

    def _uri(self, key: str) -> str:
        return f"s3://{self.bucket}/{key}"


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
