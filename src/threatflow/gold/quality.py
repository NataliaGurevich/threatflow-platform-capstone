"""Fail-closed quality gates for vulnerability-priority Gold datasets."""

from __future__ import annotations

from dataclasses import dataclass

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from threatflow.gold.vulnerability_priority import ALLOWED_PRIORITY_TIERS, GOLD_SCHEMA_VERSION

DETAIL_SCHEMA = (
    ("snapshot_date", "date"),
    ("source_cutoff", "timestamp"),
    ("cve_id", "string"),
    ("priority_tier", "string"),
    ("priority_reason", "string"),
    ("is_kev", "boolean"),
    ("vendor_project", "string"),
    ("product", "string"),
    ("vulnerability_name", "string"),
    ("known_ransomware_campaign_use", "string"),
    ("kev_date_added", "date"),
    ("cisa_due_date", "date"),
    ("nvd_published", "timestamp"),
    ("nvd_last_modified", "timestamp"),
    ("cvss_version", "string"),
    ("cvss_score", "double"),
    ("cvss_severity", "string"),
    ("epss_score_date", "date"),
    ("epss_score", "double"),
    ("epss_percentile", "double"),
    ("epss_7d_ago", "double"),
    ("epss_7d_change", "double"),
    ("generated_at", "timestamp"),
    ("policy_version", "string"),
    ("input_fingerprint", "string"),
)
SUMMARY_SCHEMA = (
    ("snapshot_date", "date"),
    ("priority_tier", "string"),
    ("vulnerability_count", "bigint"),
    ("ransomware_count", "bigint"),
    ("overdue_kev_count", "bigint"),
    ("critical_count", "bigint"),
    ("average_epss", "double"),
    ("maximum_epss", "double"),
    ("generated_at", "timestamp"),
    ("policy_version", "string"),
    ("input_fingerprint", "string"),
)


class GoldQualityError(ValueError):
    """Raised when a Gold dataset violates one or more publication invariants."""


@dataclass(frozen=True)
class GoldQualityReport:
    detail_count: int
    summary_count: int
    tier_counts: dict[str, int]


def validate_vulnerability_priority_gold(
    detail: DataFrame,
    summary: DataFrame,
) -> GoldQualityReport:
    """Validate schemas, row invariants, uniqueness, and detail-summary reconciliation."""
    issues = [
        *_schema_issues(detail, DETAIL_SCHEMA, "detail"),
        *_schema_issues(summary, SUMMARY_SCHEMA, "summary"),
    ]
    if issues:
        raise GoldQualityError("; ".join(issues))

    detail_metrics = detail.agg(
        F.count(F.lit(1)).alias("row_count"),
        F.sum(
            F.when(F.col("snapshot_date").isNull() | F.col("cve_id").isNull(), 1).otherwise(0)
        ).alias("null_key_count"),
        F.sum(
            F.when(F.col("priority_tier").isNull(), 1).otherwise(0)
        ).alias("null_tier_count"),
        F.sum(
            F.when(F.col("priority_reason").isNull(), 1).otherwise(0)
        ).alias("null_reason_count"),
        F.sum(
            F.when(F.col("cvss_severity").isNull(), 1).otherwise(0)
        ).alias("null_severity_count"),
        F.sum(
            F.when(~F.col("priority_tier").isin(*ALLOWED_PRIORITY_TIERS), 1).otherwise(0)
        ).alias("invalid_tier_count"),
        _invalid_probability_count("epss_score").alias("invalid_epss_score_count"),
        _invalid_probability_count("epss_percentile").alias("invalid_percentile_count"),
        _invalid_probability_count("epss_7d_ago").alias("invalid_epss_7d_ago_count"),
        F.countDistinct("snapshot_date").alias("snapshot_date_count"),
        F.countDistinct("source_cutoff").alias("source_cutoff_count"),
        F.countDistinct("generated_at").alias("generated_at_count"),
        F.countDistinct("policy_version").alias("policy_version_count"),
        F.countDistinct("input_fingerprint").alias("fingerprint_count"),
    ).first()
    assert detail_metrics is not None
    metric_labels = {
        "null_key_count": "detail has null business keys",
        "null_tier_count": "detail has null priority tiers",
        "null_reason_count": "detail has null priority reasons",
        "null_severity_count": "detail has null CVSS severities",
        "invalid_tier_count": "detail has invalid priority tiers",
        "invalid_epss_score_count": "detail has EPSS scores outside [0, 1]",
        "invalid_percentile_count": "detail has EPSS percentiles outside [0, 1]",
        "invalid_epss_7d_ago_count": "detail has prior EPSS scores outside [0, 1]",
    }
    for metric, label in metric_labels.items():
        if detail_metrics[metric]:
            issues.append(f"{label}: {detail_metrics[metric]}")
    if detail_metrics["row_count"] > 0:
        for metric, label in (
            ("snapshot_date_count", "snapshot_date"),
            ("source_cutoff_count", "source_cutoff"),
            ("generated_at_count", "generated_at"),
            ("policy_version_count", "policy_version"),
            ("fingerprint_count", "input_fingerprint"),
        ):
            if detail_metrics[metric] != 1:
                issues.append(f"detail must contain exactly one {label}")

    duplicate_detail_count = _duplicate_key_count(detail, ["snapshot_date", "cve_id"])
    if duplicate_detail_count:
        issues.append(f"detail has duplicate business keys: {duplicate_detail_count}")

    summary_metrics = summary.agg(
        F.count(F.lit(1)).alias("row_count"),
        F.sum(
            F.when(
                F.col("snapshot_date").isNull() | F.col("priority_tier").isNull(), 1
            ).otherwise(0)
        ).alias("null_key_count"),
        F.sum(
            F.when(~F.col("priority_tier").isin(*ALLOWED_PRIORITY_TIERS), 1).otherwise(0)
        ).alias("invalid_tier_count"),
        F.sum(
            F.when(
                (F.col("vulnerability_count") < 0)
                | (F.col("ransomware_count") < 0)
                | (F.col("overdue_kev_count") < 0)
                | (F.col("critical_count") < 0),
                1,
            ).otherwise(0)
        ).alias("negative_count_rows"),
        F.countDistinct("snapshot_date").alias("snapshot_date_count"),
        F.countDistinct("generated_at").alias("generated_at_count"),
        F.countDistinct("policy_version").alias("policy_version_count"),
        F.countDistinct("input_fingerprint").alias("fingerprint_count"),
    ).first()
    assert summary_metrics is not None
    if summary_metrics["row_count"] != len(ALLOWED_PRIORITY_TIERS):
        issues.append("summary must contain exactly one row for every priority tier")
    if summary_metrics["null_key_count"]:
        issues.append(f"summary has null business keys: {summary_metrics['null_key_count']}")
    if summary_metrics["invalid_tier_count"]:
        issues.append(
            f"summary has invalid priority tiers: {summary_metrics['invalid_tier_count']}"
        )
    if summary_metrics["negative_count_rows"]:
        issues.append(f"summary has negative counts: {summary_metrics['negative_count_rows']}")
    for metric, label in (
        ("snapshot_date_count", "snapshot_date"),
        ("generated_at_count", "generated_at"),
        ("policy_version_count", "policy_version"),
        ("fingerprint_count", "input_fingerprint"),
    ):
        if summary_metrics[metric] != 1:
            issues.append(f"summary must contain exactly one {label}")

    duplicate_summary_count = _duplicate_key_count(summary, ["snapshot_date", "priority_tier"])
    if duplicate_summary_count:
        issues.append(f"summary has duplicate business keys: {duplicate_summary_count}")

    reconciliation = _reconciliation_issues(detail, summary)
    issues.extend(reconciliation)
    if issues:
        raise GoldQualityError("; ".join(issues))

    tier_counts = {
        row["priority_tier"]: row["vulnerability_count"]
        for row in summary.select("priority_tier", "vulnerability_count").collect()
    }
    return GoldQualityReport(
        detail_count=detail_metrics["row_count"],
        summary_count=summary_metrics["row_count"],
        tier_counts=tier_counts,
    )


def _schema_issues(
    frame: DataFrame,
    expected: tuple[tuple[str, str], ...],
    label: str,
) -> list[str]:
    actual = tuple((field.name, field.dataType.simpleString()) for field in frame.schema.fields)
    if actual == expected:
        return []
    return [f"{label} schema does not match Gold schema version {GOLD_SCHEMA_VERSION}"]


def _invalid_probability_count(column: str):
    return F.sum(
        F.when(
            F.col(column).isNotNull() & ((F.col(column) < 0) | (F.col(column) > 1)),
            1,
        ).otherwise(0)
    )


def _duplicate_key_count(frame: DataFrame, columns: list[str]) -> int:
    row = (
        frame.groupBy(*columns)
        .count()
        .where(F.col("count") > 1)
        .agg(F.count(F.lit(1)).alias("duplicate_count"))
        .first()
    )
    return row["duplicate_count"] if row is not None else 0


def _reconciliation_issues(detail: DataFrame, summary: DataFrame) -> list[str]:
    expected = detail.groupBy("priority_tier").agg(
        F.count(F.lit(1)).cast("long").alias("expected_vulnerability_count"),
        F.sum(
            F.when(F.col("known_ransomware_campaign_use") == "Known", 1).otherwise(0)
        )
        .cast("long")
        .alias("expected_ransomware_count"),
        F.sum(
            F.when(
                F.col("is_kev")
                & F.col("cisa_due_date").isNotNull()
                & (F.col("cisa_due_date") < F.col("snapshot_date")),
                1,
            ).otherwise(0)
        )
        .cast("long")
        .alias("expected_overdue_kev_count"),
        F.sum(F.when(F.col("cvss_severity") == "CRITICAL", 1).otherwise(0))
        .cast("long")
        .alias("expected_critical_count"),
        F.avg("epss_score").cast("double").alias("expected_average_epss"),
        F.max("epss_score").cast("double").alias("expected_maximum_epss"),
    )
    comparison = summary.join(expected, "priority_tier", "left").where(
        ~F.col("vulnerability_count").eqNullSafe(
            F.coalesce(F.col("expected_vulnerability_count"), F.lit(0))
        )
        | ~F.col("ransomware_count").eqNullSafe(
            F.coalesce(F.col("expected_ransomware_count"), F.lit(0))
        )
        | ~F.col("overdue_kev_count").eqNullSafe(
            F.coalesce(F.col("expected_overdue_kev_count"), F.lit(0))
        )
        | ~F.col("critical_count").eqNullSafe(
            F.coalesce(F.col("expected_critical_count"), F.lit(0))
        )
        | ~F.col("average_epss").eqNullSafe(F.col("expected_average_epss"))
        | ~F.col("maximum_epss").eqNullSafe(F.col("expected_maximum_epss"))
    )
    mismatched = comparison.select("priority_tier").limit(1).collect()
    issues = []
    if mismatched:
        issues.append(
            f"summary does not reconcile with detail for {mismatched[0]['priority_tier']}"
        )

    detail_identity = detail.select(
        "snapshot_date", "generated_at", "policy_version", "input_fingerprint"
    ).distinct()
    summary_identity = summary.select(
        "snapshot_date", "generated_at", "policy_version", "input_fingerprint"
    ).distinct()
    if (
        detail_identity.limit(1).count()
        and detail_identity.exceptAll(summary_identity).limit(1).count()
    ):
        issues.append("detail and summary publication identities differ")
    return issues
