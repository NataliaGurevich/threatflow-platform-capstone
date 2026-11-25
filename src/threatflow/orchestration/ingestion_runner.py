"""Small, Airflow-independent entry points around existing ingestion services."""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

from threatflow.orchestration.date_windows import date_chunks, nvd_recovery_window, utc_day

LOG = logging.getLogger(__name__)
SOURCES = frozenset({"nvd", "cisa", "epss"})
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class IngestionResult:
    source: str
    records_fetched: int
    records_accepted: int
    started_at: datetime
    finished_at: datetime
    missing_dates: int = 0
    bronze_objects_created: int = 0
    bronze_objects_reused: int = 0


def validate_backfill(sources, start_date, end_date, nvd_mode="published", max_days=31):
    if (
        not isinstance(sources, list)
        or not sources
        or len(sources) != len(set(sources))
        or set(sources) - SOURCES
    ):
        raise ValueError("sources must be a nonempty list of distinct nvd, cisa, epss")
    if not isinstance(start_date, str) or not isinstance(end_date, str):
        raise ValueError("start_date and end_date must be ISO YYYY-MM-DD dates")
    if not _ISO_DATE.fullmatch(start_date) or not _ISO_DATE.fullmatch(end_date):
        raise ValueError("start_date and end_date must be ISO YYYY-MM-DD dates")
    try:
        start, end = date.fromisoformat(start_date), date.fromisoformat(end_date)
    except (TypeError, ValueError) as exc:
        raise ValueError("start_date and end_date must be valid ISO YYYY-MM-DD dates") from exc
    effective_max_days = 366 if set(sources) == {"cisa"} else max_days
    if start > end or end > datetime.now(UTC).date() or (end - start).days + 1 > effective_max_days:
        raise ValueError("invalid or excessive backfill date range")
    if nvd_mode not in {"published", "modified"}:
        raise ValueError("nvd_mode must be published or modified")
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
        fetched, accepted = result.total_records_received, result.records_accepted
        created, reused = result.bronze_objects_created, result.bronze_objects_reused
    elif source == "cisa":
        from threatflow.ingestion.cisa_ingestion import ingest_cisa_kev

        result = ingest_cisa_kev()
        fetched, accepted = result.parsed_records, result.records_accepted
        created, reused = int(result.bronze_object_created), int(not result.bronze_object_created)
    else:
        from threatflow.ingestion.epss_ingestion import ingest_epss

        result = ingest_epss(score_date=score_date)
        fetched, accepted = result.received_records, result.records_accepted
        created, reused = int(result.bronze_object_created), int(not result.bronze_object_created)
        LOG.info(
            "stage=epss_storage score_date=%s storage_mode=aws_bronze records_accepted=%d",
            result.score_date,
            accepted,
        )
    summary = IngestionResult(
        source,
        fetched,
        accepted,
        started,
        datetime.now(UTC),
        bronze_objects_created=created,
        bronze_objects_reused=reused,
    )
    LOG.info(
        "ingestion complete source=%s mode=%s start=%s end=%s "
        "score_date=%s fetched=%d accepted=%d bronze_created=%d bronze_reused=%d "
        "duration_seconds=%.2f",
        source,
        mode,
        start,
        end,
        score_date,
        fetched,
        accepted,
        created,
        reused,
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
        from threatflow.config import Settings
        from threatflow.s3_pipeline_state import S3PipelineState

        settings = Settings()
        state = S3PipelineState.from_settings(settings)
        LOG.info("stage=nvd_checkpoint_read backend=s3")
        previous = state.nvd_covered_until()
        start, end = nvd_recovery_window(
            interval_end, settings.nvd_modified_lookback_hours, previous
        )
        # The source pool and max_active_runs serialize normal Airflow execution.
        # Conditional S3 checkpoint writes reject an unexpected concurrent update.
        cursor = start
        result = None
        while cursor < end:
            finish = min(end, cursor + timedelta(days=120))
            LOG.info("stage=nvd_chunk_start start=%s end=%s", cursor, finish)
            result = _execute(source, cursor, finish)
            state.advance_nvd_covered_until(finish)
            cursor = finish
            LOG.info("stage=nvd_checkpoint_advanced backend=s3 covered_until=%s", finish)
        return result
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
    if (
        source not in {"nvd", "cisa", "epss"}
        or start_date > end_date
        or chunk_days < 1
        or chunk_days > 31
    ):
        raise ValueError("invalid backfill source, range, or chunk size")
    if source == "nvd" and mode not in {"default", "published", "modified"}:
        raise ValueError("invalid NVD mode")
    started = datetime.now(UTC)
    fetched = accepted = missing = created = reused = 0
    if source == "cisa":
        # The CISA feed is a current catalog. A requested date range performs one
        # current snapshot synchronization instead of duplicating today's feed.
        result = _execute("cisa")
        return IngestionResult(
            source,
            result.records_fetched,
            result.records_accepted,
            started,
            datetime.now(UTC),
            bronze_objects_created=result.bronze_objects_created,
            bronze_objects_reused=result.bronze_objects_reused,
        )
    for first, last in date_chunks(start_date, end_date, chunk_days):
        if source == "nvd":
            begin, _ = utc_day(first)
            _, finish = utc_day(last)
            result = _execute(source, begin, finish, "published" if mode == "default" else mode)
            fetched += result.records_fetched
            accepted += result.records_accepted
            created += result.bronze_objects_created
            reused += result.bronze_objects_reused
        else:
            for ordinal in range((last - first).days + 1):
                score_date = first + timedelta(days=ordinal)
                try:
                    result = _execute(source, score_date=score_date)
                except Exception as exc:
                    from threatflow.ingestion.epss_client import EpssArchiveNotFound

                    if not isinstance(exc, EpssArchiveNotFound):
                        raise
                    missing += 1
                    LOG.warning("stage=archive_missing source=epss score_date=%s", score_date)
                    continue
                fetched += result.records_fetched
                accepted += result.records_accepted
                created += result.bronze_objects_created
                reused += result.bronze_objects_reused
    return IngestionResult(
        source,
        fetched,
        accepted,
        started,
        datetime.now(UTC),
        missing,
        created,
        reused,
    )
