"""Ingest one current or explicitly dated EPSS dataset."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import create_engine, func, select

from threatflow.config import Settings
from threatflow.ingestion.epss_client import EpssClient
from threatflow.ingestion.epss_parser import extract_score_date, parse_dataset
from threatflow.ingestion.epss_validation import validate_completeness
from threatflow.models.epss import EpssCurrentScore, EpssDailySummary, EpssScore
from threatflow.raw_storage import (
    RawArtifactStore,
    create_raw_artifact_store,
    create_validated_replica_store,
    replicate_validated_artifact,
)
from threatflow.repository.epss_repository import prune_history, upsert_records, upsert_summary
from threatflow.repository.raw_artifact_repository import record_artifact

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
    inserted_records: int
    updated_records: int
    pruned_records: int
    summary_only: bool


def ingest_epss(
    *,
    score_date: date | None = None,
    client: EpssClient | None = None,
    settings: Settings | None = None,
    raw_store: RawArtifactStore | None = None,
    replica_store: RawArtifactStore | None = None,
) -> EpssIngestionResult:
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    acquired = datetime.now(UTC)
    client = client or EpssClient(
        connect_timeout=settings.http_connect_timeout,
        read_timeout=settings.http_read_timeout,
        retries=settings.http_retries,
    )
    raw = client.fetch(score_date)
    artifact = raw_store.store("epss", raw, acquired, ".csv.gz")
    if score_date is None:
        resolved = extract_score_date(raw)
    else:
        resolved = score_date
    records = parse_dataset(raw, resolved)
    validate_completeness(len(records), resolved)
    engine = create_engine(settings.database_url)
    try:
        from sqlalchemy.orm import Session

        with Session(engine) as session:
            adjacent = session.scalar(
                select(EpssDailySummary.record_count).where(
                    EpssDailySummary.score_date == resolved - timedelta(days=1)
                )
            )
        validate_completeness(len(records), resolved, adjacent)
        if replica_store is None:
            replica_store = create_validated_replica_store(settings)
        replica = replicate_validated_artifact(
            replica_store, artifact, raw, acquired
        )

        with engine.begin() as connection:
            with Session(bind=connection) as session:
                score_start = datetime.combine(resolved, datetime.min.time(), UTC)
                record_artifact(
                    session,
                    artifact,
                    acquired,
                    request_mode="score_date",
                    requested_start=score_start,
                    requested_end=score_start + timedelta(days=1),
                    record_count=len(records),
                    ingestion_run_id=os.getenv("AIRFLOW_CTX_DAG_RUN_ID"),
                    additional_locations=(replica,) if replica is not None else (),
                )
                latest_date = session.scalar(select(func.max(EpssCurrentScore.score_date)))
                cutoff = (latest_date or resolved) - timedelta(
                    days=settings.epss_history_retention_days - 1
                )
                summary_only = resolved < cutoff
                if summary_only:
                    upsert_summary(session, records)
                    inserted = updated = pruned = 0
                    LOGGER.info(
                        "stage=summary_only score_date=%s records=%d retention_cutoff=%s",
                        resolved,
                        len(records),
                        cutoff,
                    )
                else:
                    inserted, updated = upsert_records(session, records)
                    latest_date = session.scalar(select(func.max(EpssScore.score_date)))
                    pruned = prune_history(
                        session,
                        latest_date=latest_date or resolved,
                        retention_days=settings.epss_history_retention_days,
                    )
                session.flush()
    finally:
        engine.dispose()
    return EpssIngestionResult(
        "epss",
        resolved,
        acquired,
        artifact.uri,
        artifact.sha256,
        len(raw),
        len(records),
        inserted,
        updated,
        pruned,
        summary_only,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ingest one EPSS daily dataset")
    parser.add_argument("--score-date", type=date.fromisoformat)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    print(ingest_epss(score_date=args.score_date))
