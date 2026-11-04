"""Small, Airflow-independent entry points around existing ingestion services."""

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from threatflow.orchestration.date_windows import date_chunks, nvd_recovery_window, utc_day

LOG = logging.getLogger(__name__)
SOURCES = frozenset({"nvd", "cisa", "epss"})


@dataclass(frozen=True)
class IngestionResult:
    source: str
    records_fetched: int
    records_written: int
    started_at: datetime
    finished_at: datetime


def validate_backfill(sources, start_date, end_date, nvd_mode="published", max_days=31):
    if (
        not isinstance(sources, list)
        or not sources
        or len(sources) != len(set(sources))
        or set(sources) - SOURCES
    ):
        raise ValueError("sources must be a nonempty list of distinct nvd, cisa, epss")
    try:
        start, end = date.fromisoformat(start_date), date.fromisoformat(end_date)
    except (TypeError, ValueError) as exc:
        raise ValueError("start_date and end_date must be ISO dates") from exc
    if start > end or end > datetime.now(UTC).date() or (end - start).days + 1 > max_days:
        raise ValueError("invalid or excessive backfill date range")
    if nvd_mode not in {"published", "modified"}:
        raise ValueError("nvd_mode must be published or modified")
    if "cisa" in sources:
        raise ValueError(
            "CISA historical snapshots are unavailable; run cisa_daily for snapshot_sync"
        )
    return start, end


def _execute(source, start=None, end=None, mode="modified", score_date=None):
    if source not in SOURCES:
        raise ValueError(f"unsupported source: {source}")
    started = datetime.now(UTC)
    LOG.info(
        "stage=source_fetch_start source=%s mode=%s start=%s end=%s score_date=%s",
        source,
        mode,
        start,
        end,
        score_date,
    )
    if source == "nvd":
        from threatflow.ingestion.nvd_ingestion import ingest_nvd_cves

        result = ingest_nvd_cves(start=start, end=end, mode=mode)
        fetched, written = (
            result.total_records_received,
            result.inserted_records + result.updated_records,
        )
    elif source == "cisa":
        from threatflow.ingestion.cisa_ingestion import ingest_cisa_kev

        result = ingest_cisa_kev()
        fetched, written = result.parsed_records, result.inserted_records + result.updated_records
    else:
        from threatflow.ingestion.epss_ingestion import ingest_epss

        result = ingest_epss(score_date=score_date)
        fetched, written = result.received_records, result.inserted_records + result.updated_records
    summary = IngestionResult(source, fetched, written, started, datetime.now(UTC))
    LOG.info(
        "ingestion complete source=%s mode=%s start=%s end=%s "
        "score_date=%s fetched=%d written=%d duration_seconds=%.2f",
        source,
        mode,
        start,
        end,
        score_date,
        fetched,
        written,
        (summary.finished_at - started).total_seconds(),
    )
    return summary


def run_daily(source: str, interval_start: datetime, interval_end: datetime) -> IngestionResult:
    # Airflow CronTriggerTimetable supplies a point interval (start == end).
    if (
        source not in SOURCES
        or interval_start.tzinfo is None
        or interval_end.tzinfo is None
        or interval_start > interval_end
    ):
        raise ValueError("invalid daily source or interval")
    if source == "nvd":
        from sqlalchemy import create_engine, text

        from threatflow.config import Settings

        settings = Settings()
        start, end = nvd_recovery_window(interval_end, settings.nvd_modified_lookback_hours, None)
        engine = create_engine(settings.database_url)
        try:
            # One source-wide lock also serializes duplicate and overlapping daily runs.
            with engine.connect().execution_options(
                isolation_level="AUTOCOMMIT"
            ) as lock_connection:
                lock_connection.execute(text("SELECT pg_advisory_lock(74211901)"))
                try:
                    LOG.info("stage=nvd_checkpoint_read")
                    previous = lock_connection.execute(
                        text("SELECT covered_until FROM ingestion_checkpoints WHERE source = 'nvd'")
                    ).scalar_one_or_none()
                    start, end = nvd_recovery_window(
                        interval_end, settings.nvd_modified_lookback_hours, previous
                    )
                    # NVD permits at most 120 days per modified query. Commit the
                    # checkpoint after each successful chunk; failed chunks stay uncovered.
                    cursor = start
                    result = None
                    while cursor < end:
                        finish = min(end, cursor + timedelta(days=120))
                        LOG.info("stage=nvd_chunk_start start=%s end=%s", cursor, finish)
                        result = _execute(source, cursor, finish)
                        with engine.begin() as checkpoint:
                            checkpoint.execute(
                                text("""
                                INSERT INTO ingestion_checkpoints (source, covered_until)
                                VALUES ('nvd', :finish)
                                ON CONFLICT (source) DO UPDATE SET covered_until =
                                    GREATEST(ingestion_checkpoints.covered_until,
                                             EXCLUDED.covered_until)
                            """),
                                {"finish": finish},
                            )
                        cursor = finish
                        LOG.info("stage=nvd_checkpoint_advanced covered_until=%s", finish)
                    return result
                finally:
                    lock_connection.execute(text("SELECT pg_advisory_unlock(74211901)"))
        finally:
            engine.dispose()
    if source == "epss":
        # The just-completed UTC calendar day is available after the 06:00 schedule;
        # unavailable archives fail explicitly (HTTP 404), allowing manual retry.
        return _execute(
            source, score_date=(interval_end.astimezone(UTC) - timedelta(days=1)).date()
        )
    return _execute(source)


def run_backfill(
    source: str, start_date: date, end_date: date, mode: str = "default", chunk_days: int = 7
) -> IngestionResult:
    if source not in {"nvd", "epss"} or start_date > end_date or chunk_days < 1 or chunk_days > 31:
        raise ValueError("invalid backfill source, range, or chunk size")
    if source == "nvd" and mode not in {"default", "published", "modified"}:
        raise ValueError("invalid NVD mode")
    started = datetime.now(UTC)
    fetched = written = 0
    for first, last in date_chunks(start_date, end_date, chunk_days):
        if source == "nvd":
            begin, _ = utc_day(first)
            _, finish = utc_day(last)
            result = _execute(source, begin, finish, "published" if mode == "default" else mode)
            fetched += result.records_fetched
            written += result.records_written
        else:
            for ordinal in range((last - first).days + 1):
                result = _execute(source, score_date=first + timedelta(days=ordinal))
                fetched += result.records_fetched
                written += result.records_written
    return IngestionResult(source, fetched, written, started, datetime.now(UTC))
