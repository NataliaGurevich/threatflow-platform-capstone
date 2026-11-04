"""Run one complete CISA KEV ingestion."""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine, func, select

from threatflow.config import Settings
from threatflow.derivations.cisa_changes import (
    calculate_changes,
    json_safe_record,
    resolve_cisa_artifact_path,
)
from threatflow.ingestion.cisa_client import CisaClient, CisaGitHistoryClient
from threatflow.ingestion.cisa_parser import parse_catalog
from threatflow.models.cisa import CisaKevVulnerability
from threatflow.models.raw_artifact import RawArtifact
from threatflow.raw_storage import store_raw_artifact
from threatflow.repository.cisa_change_repository import upsert_changes
from threatflow.repository.cisa_repository import upsert_records
from threatflow.repository.raw_artifact_repository import record_artifact

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionResult:
    source: str
    acquired_at: datetime
    raw_artifact_path: str
    sha256: str
    downloaded_bytes: int
    parsed_records: int
    inserted_records: int
    updated_records: int
    change_records: int


@dataclass(frozen=True)
class CisaHistoryResult:
    source: str
    start_date: date
    end_date: date
    snapshots: int
    parsed_records: int
    downloaded_bytes: int
    invalid_snapshots: int = 0


def ingest_cisa_kev(
    *, client: CisaClient | None = None, settings: Settings | None = None
) -> IngestionResult:
    settings = settings or Settings()
    acquired_at = datetime.now(UTC)
    LOGGER.info("CISA KEV ingestion started", extra={"source": "cisa_kev"})
    content = (
        client
        or CisaClient(
            connect_timeout=settings.http_connect_timeout,
            read_timeout=settings.http_read_timeout,
            retries=settings.http_retries,
        )
    ).fetch()
    artifact = store_raw_artifact(
        "cisa_kev", content, acquired_at, ".json", raw_data_dir=settings.raw_data_dir
    )
    records = parse_catalog(content)
    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            from sqlalchemy.orm import Session

            with Session(bind=connection) as session:
                known_artifact = session.scalar(
                    select(RawArtifact.id).where(
                        RawArtifact.source == "cisa_kev",
                        RawArtifact.sha256 == artifact.sha256,
                    )
                )
                previous_artifact = None
                if known_artifact is None:
                    previous_artifact = session.scalar(
                        select(RawArtifact)
                        .where(
                            RawArtifact.source == "cisa_kev",
                            RawArtifact.request_mode.in_(["snapshot", "git_history"]),
                            RawArtifact.sha256 != artifact.sha256,
                        )
                        .order_by(
                            func.coalesce(
                                RawArtifact.requested_start, RawArtifact.last_seen_at
                            ).desc()
                        )
                        .limit(1)
                    )
                record_artifact(
                    session,
                    artifact,
                    acquired_at,
                    request_mode="snapshot",
                    record_count=len(records),
                    ingestion_run_id=os.getenv("AIRFLOW_CTX_DAG_RUN_ID"),
                )
                previous = (
                    session.scalar(select(func.count()).select_from(CisaKevVulnerability)) or 0
                )
                if previous >= 20 and len(records) < previous * 0.8:
                    raise ValueError(
                        f"CISA KEV catalog shrank unexpectedly: "
                        f"{len(records)} versus {previous} stored"
                    )
                changes = []
                if known_artifact is None:
                    previous = None
                    if previous_artifact is not None:
                        previous_path = resolve_cisa_artifact_path(
                            previous_artifact.storage_path, Path(settings.raw_data_dir)
                        )
                        previous = {
                            record["cve_id"]: json_safe_record(record)
                            for record in parse_catalog(previous_path.read_bytes())
                        }
                    current = {record["cve_id"]: json_safe_record(record) for record in records}
                    changes = calculate_changes(
                        previous,
                        current,
                        commit_sha=artifact.sha256,
                        committed_at=acquired_at,
                        revision_type="content_sha256",
                    )
                    upsert_changes(session, changes)
                inserted, updated = upsert_records(session, records)
                session.flush()
        result = IngestionResult(
            "cisa_kev",
            acquired_at,
            str(artifact.path),
            artifact.sha256,
            len(content),
            len(records),
            inserted,
            updated,
            len(changes),
        )
        LOGGER.info("CISA KEV ingestion finished", extra=asdict(result))
        return result
    finally:
        engine.dispose()


def backfill_cisa_kev(
    start_date: date,
    end_date: date,
    *,
    client: CisaGitHistoryClient | None = None,
    settings: Settings | None = None,
) -> CisaHistoryResult:
    """Store validated official Git snapshots without regressing the current-state table."""
    if start_date > end_date:
        raise ValueError("CISA history start must not be after end")
    settings = settings or Settings()
    token = settings.github_token.get_secret_value() if settings.github_token else None
    client = client or CisaGitHistoryClient(
        token=token,
        connect_timeout=settings.http_connect_timeout,
        read_timeout=settings.http_read_timeout,
        retries=settings.http_retries,
    )
    commits = client.list_commits(start_date, end_date)
    engine = create_engine(settings.database_url)
    total_records = total_bytes = invalid_snapshots = 0
    try:
        with engine.connect() as connection:
            completed_revisions = set(
                connection.scalars(
                    select(RawArtifact.source_revision).where(
                        RawArtifact.source == "cisa_kev",
                        RawArtifact.request_mode.in_(["git_history", "git_history_invalid"]),
                        RawArtifact.source_revision.in_([commit.sha for commit in commits]),
                    )
                )
            )
        for commit in commits:
            if commit.sha in completed_revisions:
                LOGGER.info("stage=cisa_git_snapshot_skipped revision=%s", commit.sha)
                continue
            for attempt in range(settings.http_retries + 1):
                content = client.fetch_snapshot(commit.sha)
                acquired_at = datetime.now(UTC)
                artifact = store_raw_artifact(
                    "cisa_kev", content, acquired_at, ".json", raw_data_dir=settings.raw_data_dir
                )
                try:
                    records = parse_catalog(content)
                except ValueError as exc:
                    if attempt >= settings.http_retries:
                        with engine.begin() as connection:
                            from sqlalchemy.orm import Session

                            with Session(bind=connection) as session:
                                record_artifact(
                                    session,
                                    artifact,
                                    acquired_at,
                                    request_mode="git_history_invalid",
                                    requested_start=commit.committed_at,
                                    requested_end=commit.committed_at + timedelta(microseconds=1),
                                    ingestion_run_id=os.getenv("AIRFLOW_CTX_DAG_RUN_ID"),
                                    source_revision=commit.sha,
                                )
                        total_bytes += len(content)
                        invalid_snapshots += 1
                        LOGGER.error(
                            "stage=cisa_git_snapshot_invalid revision=%s attempts=%d "
                            "skipped=true error=%s",
                            commit.sha,
                            attempt + 1,
                            exc,
                        )
                        records = None
                        break
                    LOGGER.warning(
                        "stage=cisa_git_snapshot_invalid revision=%s attempt=%d retrying=true",
                        commit.sha,
                        attempt + 1,
                    )
                    continue
                break
            if records is None:
                continue
            with engine.begin() as connection:
                from sqlalchemy.orm import Session

                with Session(bind=connection) as session:
                    record_artifact(
                        session,
                        artifact,
                        acquired_at,
                        request_mode="git_history",
                        requested_start=commit.committed_at,
                        requested_end=commit.committed_at + timedelta(microseconds=1),
                        record_count=len(records),
                        ingestion_run_id=os.getenv("AIRFLOW_CTX_DAG_RUN_ID"),
                        source_revision=commit.sha,
                    )
            total_records += len(records)
            total_bytes += len(content)
            LOGGER.info(
                "stage=cisa_git_snapshot revision=%s committed_at=%s records=%d",
                commit.sha,
                commit.committed_at.isoformat(),
                len(records),
            )
    finally:
        engine.dispose()
    return CisaHistoryResult(
        "cisa_kev",
        start_date,
        end_date,
        len(commits),
        total_records,
        total_bytes,
        invalid_snapshots,
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ingest_cisa_kev()
