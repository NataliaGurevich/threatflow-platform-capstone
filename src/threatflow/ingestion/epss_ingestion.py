"""Ingest one current or explicitly dated EPSS dataset."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from threatflow.config import Settings
from threatflow.ingestion.epss_client import EpssClient
from threatflow.ingestion.epss_parser import extract_score_date, parse_dataset
from threatflow.ingestion.epss_validation import validate_completeness
from threatflow.raw_storage import (
    RawArtifactStore,
    create_quarantine_artifact_store,
    create_raw_artifact_store,
)
from threatflow.s3_pipeline_state import S3PipelineState

LOGGER = logging.getLogger(__name__)

@dataclass(frozen=True)
class EpssIngestionResult:
    source: str
    score_date: date
    acquired_at: datetime
    raw_artifact_path: str
    sha256: str
    downloaded_bytes: int
    received_records: int
    records_accepted: int
    bronze_object_created: bool


def ingest_epss(
    *,
    score_date: date | None = None,
    client: EpssClient | None = None,
    settings: Settings | None = None,
    raw_store: RawArtifactStore | None = None,
    quarantine_store: RawArtifactStore | None = None,
    state_store: S3PipelineState | None = None,
) -> EpssIngestionResult:
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    if raw_store.backend != "s3":
        raise ValueError("EPSS ingestion requires the S3 Bronze backend")
    acquired = datetime.now(UTC)
    client = client or EpssClient(
        connect_timeout=settings.http_connect_timeout,
        read_timeout=settings.http_read_timeout,
        retries=settings.http_retries,
    )
    raw = client.fetch(score_date)
    try:
        if score_date is None:
            resolved = extract_score_date(raw)
        else:
            resolved = score_date
        records = parse_dataset(raw, resolved)
        minimum_override = settings.epss_minimum_count_overrides.get(resolved)
        validate_completeness(
            len(records),
            resolved,
            minimum_count_override=minimum_override,
        )
        state_store = state_store or S3PipelineState.from_settings(settings)
        adjacent = state_store.epss_record_count(resolved - timedelta(days=1))
        validate_completeness(
            len(records),
            resolved,
            adjacent,
            minimum_override,
        )
    except ValueError:
        quarantine_store = quarantine_store or create_quarantine_artifact_store(settings)
        artifact = quarantine_store.store(
            "epss",
            raw,
            acquired,
            ".csv.gz",
            metadata={
                "artifact-status": "quarantined",
                "failure-stage": "bronze-data-quality",
            },
        )
        LOGGER.exception("stage=bronze_quarantined source=epss uri=%s", artifact.uri)
        raise
    artifact = raw_store.store(
        "epss",
        raw,
        acquired,
        ".csv.gz",
        metadata={
            "request-mode": "score_date",
            "score-date": resolved.isoformat(),
            "record-count": str(len(records)),
        },
    )
    return EpssIngestionResult(
        "epss",
        resolved,
        acquired,
        artifact.uri,
        artifact.sha256,
        len(raw),
        len(records),
        len(records),
        artifact.created,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest one EPSS daily dataset")
    parser.add_argument("--score-date", type=date.fromisoformat)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(ingest_epss(score_date=args.score_date))
