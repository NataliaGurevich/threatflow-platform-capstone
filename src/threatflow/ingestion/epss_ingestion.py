"""Ingest one current or explicitly dated EPSS dataset."""

from __future__ import annotations

import gzip
import logging
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import create_engine, func, select

from threatflow.config import Settings
from threatflow.ingestion.epss_client import EpssClient
from threatflow.ingestion.epss_parser import parse_dataset
from threatflow.models.epss import EpssCurrentScore, EpssDailySummary, EpssScore
from threatflow.raw_storage import RawArtifactStore, create_raw_artifact_store
from threatflow.repository.epss_repository import prune_history, upsert_records, upsert_summary
from threatflow.repository.raw_artifact_repository import record_artifact

LOGGER = logging.getLogger(__name__)

# Conservative floors by dataset era. The published gzip header has model_version and
# score_date, but no row count. Revisit these floors as the CVE corpus grows.
MIN_ROWS_BY_YEAR = {
    2021: 50_000,
    2022: 75_000,
    2023: 100_000,
    2024: 130_000,
    2025: 160_000,
    2026: 180_000,
}


def validate_completeness(count: int, score_date: date, adjacent_count: int | None = None):
    floor = MIN_ROWS_BY_YEAR.get(score_date.year, MIN_ROWS_BY_YEAR[max(MIN_ROWS_BY_YEAR)])
    if count < floor or (adjacent_count and count < adjacent_count * 0.8):
        raise ValueError(
            f"EPSS dataset incomplete for {score_date}: {count} rows; "
            f"minimum {floor}, adjacent day {adjacent_count}"
        )


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
        try:
            first = gzip.decompress(raw).decode("utf-8-sig").splitlines()[0]
        except (OSError, EOFError, UnicodeDecodeError, IndexError) as exc:
            raise ValueError(
                "cannot establish current EPSS score date from source metadata"
            ) from exc
        import re

        match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", first)
        if not match:
            raise ValueError("current EPSS source has no authoritative score_date metadata")
        resolved = date.fromisoformat(match.group(1))
    else:
        resolved = score_date
    records = parse_dataset(raw, resolved)
    validate_completeness(len(records), resolved)
    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            from sqlalchemy.orm import Session

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
                )
                adjacent = session.scalar(
                    select(EpssDailySummary.record_count).where(
                        EpssDailySummary.score_date == resolved - timedelta(days=1)
                    )
                )
                validate_completeness(len(records), resolved, adjacent)
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
