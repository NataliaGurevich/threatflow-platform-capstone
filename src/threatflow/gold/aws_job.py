"""AWS Glue orchestration for one vulnerability-priority Gold snapshot."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, date, datetime, time
from typing import Any

import boto3
from botocore.config import Config
from pyspark.storagelevel import StorageLevel

from threatflow.gold.local_publish import canonical_input_fingerprint
from threatflow.gold.s3_publish import S3GoldPublisher, S3GoldPublishResult
from threatflow.gold.s3_resolver import S3SilverResolver
from threatflow.gold.vulnerability_priority import (
    POLICY_VERSION,
    build_vulnerability_priority_daily,
    build_vulnerability_priority_summary_daily,
)

LOGGER = logging.getLogger(__name__)
_BOTO_CONFIG = Config(
    retries={"total_max_attempts": 6, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    max_pool_connections=20,
)


def run_vulnerability_priority_gold_job(
    *,
    spark: Any,
    silver_bucket: str,
    silver_prefix: str,
    gold_bucket: str,
    gold_prefix: str,
    snapshot_date: date,
    snapshot_type: str,
    nvd_history_complete: bool,
    aws_region: str | None = None,
    s3_client: Any | None = None,
) -> S3GoldPublishResult:
    """Resolve, transform, validate, and commit one S3 Gold date."""
    if snapshot_type == "OBSERVED" and not nvd_history_complete:
        raise ValueError("OBSERVED snapshots require nvd_history_complete=true")
    source_cutoff = datetime.combine(snapshot_date, time.max, tzinfo=UTC)
    generated_at = datetime.now(UTC)
    client = s3_client or boto3.client(
        "s3",
        region_name=aws_region,
        config=_BOTO_CONFIG,
    )
    resolver = S3SilverResolver(silver_bucket, silver_prefix, s3_client=client)
    plan = resolver.resolve(
        snapshot_date,
        source_cutoff=source_cutoff,
        snapshot_type=snapshot_type,
        nvd_history_complete=nvd_history_complete,
    )
    input_plan = plan.fingerprint_plan()
    fingerprint = canonical_input_fingerprint(
        input_plan,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        policy_version=POLICY_VERSION,
    )
    LOGGER.info(
        "gold_inputs_resolved snapshot_date=%s fingerprint=%s nvd_artifacts=%d",
        snapshot_date,
        fingerprint,
        len(plan.nvd),
    )
    nvd = spark.read.parquet(*(item.parquet_uri for item in plan.nvd)).persist(
        StorageLevel.DISK_ONLY
    )
    detail = None
    summary = None
    try:
        detail = build_vulnerability_priority_daily(
            nvd=nvd,
            cisa=spark.read.parquet(plan.cisa.parquet_uri),
            epss_current=spark.read.parquet(plan.epss_current.parquet_uri),
            epss_previous=spark.read.parquet(plan.epss_previous.parquet_uri),
            snapshot_date=snapshot_date,
            source_cutoff=source_cutoff,
            generated_at=generated_at,
            input_fingerprint=fingerprint,
            snapshot_type=snapshot_type,
            nvd_history_complete=nvd_history_complete,
        ).persist(StorageLevel.DISK_ONLY)
        detail.count()
        summary = build_vulnerability_priority_summary_daily(
            detail,
            snapshot_date=snapshot_date,
            generated_at=generated_at,
            input_fingerprint=fingerprint,
            snapshot_type=snapshot_type,
            nvd_history_complete=nvd_history_complete,
        ).persist(StorageLevel.DISK_ONLY)
        summary.count()
        publisher = S3GoldPublisher(gold_bucket, gold_prefix, s3_client=client)
        result = publisher.publish(
            detail,
            summary,
            input_plan=input_plan,
            snapshot_date=snapshot_date,
            source_cutoff=source_cutoff,
            generated_at=generated_at,
            input_fingerprint=fingerprint,
            snapshot_type=snapshot_type,
            nvd_history_complete=nvd_history_complete,
        )
        LOGGER.info("gold_publish_result %s", asdict(result))
        return result
    finally:
        if summary is not None:
            summary.unpersist()
        if detail is not None:
            detail.unpersist()
        nvd.unpersist()
