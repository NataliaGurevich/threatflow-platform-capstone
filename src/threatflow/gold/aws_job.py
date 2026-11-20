"""AWS Glue orchestration for one vulnerability-priority Gold snapshot."""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

import boto3
from botocore.config import Config
from pyspark.storagelevel import StorageLevel

from threatflow.gold.catalog import GoldCatalogRegistrar
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
    catalog_database: str,
    snapshot_date: date | None,
    snapshot_type: str,
    nvd_history_complete: bool,
    max_input_lag_days: int = 2,
    aws_region: str | None = None,
    s3_client: Any | None = None,
    glue_client: Any | None = None,
) -> S3GoldPublishResult:
    """Resolve, transform, validate, and commit one S3 Gold date."""
    if snapshot_type == "OBSERVED" and not nvd_history_complete:
        raise ValueError("OBSERVED snapshots require nvd_history_complete=true")
    generated_at = datetime.now(UTC)
    client = s3_client or boto3.client(
        "s3",
        region_name=aws_region,
        config=_BOTO_CONFIG,
    )
    catalog_client = glue_client or boto3.client(
        "glue",
        region_name=aws_region,
        config=_BOTO_CONFIG,
    )
    resolver = S3SilverResolver(silver_bucket, silver_prefix, s3_client=client)
    if snapshot_date is None:
        snapshot_date = resolver.select_latest_ready_snapshot_date(
            latest_allowed_date=generated_at.date() - timedelta(days=1),
            max_input_lag_days=max_input_lag_days,
        )
        LOGGER.info(
            "gold_auto_snapshot_selected snapshot_date=%s max_input_lag_days=%d",
            snapshot_date,
            max_input_lag_days,
        )
    source_cutoff = datetime.combine(snapshot_date, time.max, tzinfo=UTC)
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
        catalog_result = GoldCatalogRegistrar(
            bucket=gold_bucket,
            prefix=gold_prefix,
            database=catalog_database,
            s3_client=client,
            glue_client=catalog_client,
        ).register_commit_uri(result.product_commit_uri)
        LOGGER.info("gold_publish_result %s", asdict(result))
        LOGGER.info("gold_catalog_result %s", asdict(catalog_result))
        return result
    finally:
        if summary is not None:
            summary.unpersist()
        if detail is not None:
            detail.unpersist()
        nvd.unpersist()
