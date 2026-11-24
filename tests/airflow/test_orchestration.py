from datetime import UTC, date, datetime
from types import SimpleNamespace

import pytest

from threatflow.orchestration.date_windows import (
    date_chunks,
    nvd_daily_window,
    nvd_recovery_window,
    utc_day,
)
from threatflow.orchestration.ingestion_runner import run_backfill, run_daily, validate_backfill


def test_utc_windows_and_chunks():
    start, end = utc_day(date(2025, 12, 31))
    assert start == datetime(2025, 12, 31, tzinfo=UTC)
    assert end == datetime(2025, 12, 31, 23, 59, 59, 999000, UTC)
    assert list(date_chunks(date(2025, 12, 30), date(2026, 1, 3), 2)) == [
        (date(2025, 12, 30), date(2025, 12, 31)),
        (date(2026, 1, 1), date(2026, 1, 2)),
        (date(2026, 1, 3), date(2026, 1, 3)),
    ]
    assert nvd_daily_window(datetime(2026, 1, 1, 3, tzinfo=UTC))[0] == datetime(
        2025, 12, 30, 3, tzinfo=UTC
    )


def test_nvd_72_hour_outage_recovers_entire_gap():
    previous = datetime(2026, 1, 1, 3, tzinfo=UTC)
    resumed = datetime(2026, 1, 4, 3, tzinfo=UTC)
    assert nvd_daily_window(resumed, 48)[0] > previous
    assert nvd_recovery_window(resumed, 48, previous) == (previous, resumed)


@pytest.mark.parametrize("sources", [[], ["nvd", "nvd"], ["bad"]])
def test_invalid_backfill(sources):
    with pytest.raises(ValueError):
        validate_backfill(sources, "2025-01-01", "2025-01-02")


def test_cisa_daily_accepts_cron_trigger_point_interval(monkeypatch):
    from threatflow.orchestration import ingestion_runner as runner

    calls = []

    def fake_execute(source):
        calls.append(source)
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 1, 1, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    trigger_time = datetime(2026, 11, 4, 4, tzinfo=UTC)
    assert run_daily("cisa", trigger_time, trigger_time).source == "cisa"
    assert calls == ["cisa"]
    with pytest.raises(ValueError, match="invalid daily source or interval"):
        run_daily("cisa", trigger_time, trigger_time.replace(hour=3))
    assert calls == ["cisa"]


def test_airflow_daily_normalizes_source_and_logs_stages(monkeypatch, caplog):
    from threatflow.orchestration import airflow_tasks
    from threatflow.orchestration import ingestion_runner as runner

    now = datetime.now(UTC)
    monkeypatch.setattr(
        runner,
        "run_daily",
        lambda source, start, end: runner.IngestionResult(source, 3, 2, now, now),
    )
    caplog.set_level("INFO")

    result = airflow_tasks.daily(
        " CISA ",
        "2026-11-04T04:00:00+00:00",
        "2026-11-04T04:00:00+00:00",
    )

    assert result["source"] == "cisa"
    assert "stage=task_input" in caplog.text
    assert "stage=ingestion_complete" in caplog.text


def test_epss_daily_accepts_cron_trigger_point_interval(monkeypatch):
    from threatflow.orchestration import ingestion_runner as runner

    calls = []

    def fake_execute(source, score_date):
        calls.append((source, score_date))
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 1, 1, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    trigger_time = datetime(2026, 11, 4, 6, tzinfo=UTC)
    assert run_daily("epss", trigger_time, trigger_time).source == "epss"
    assert calls == [("epss", date(2026, 11, 3))]


def test_nvd_daily_accepts_cron_trigger_point_interval(monkeypatch):
    from threatflow import config, s3_pipeline_state
    from threatflow.orchestration import ingestion_runner as runner

    calls = []
    advanced = []

    class State:
        @classmethod
        def from_settings(cls, settings):
            return cls()

        def nvd_covered_until(self):
            return None

        def advance_nvd_covered_until(self, covered_until):
            advanced.append(covered_until)

    monkeypatch.setattr(s3_pipeline_state, "S3PipelineState", State)
    monkeypatch.setattr(
        config,
        "Settings",
        lambda: SimpleNamespace(nvd_modified_lookback_hours=48),
    )

    def fake_execute(source, start, end):
        calls.append((source, start, end))
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 1, 1, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    trigger_time = datetime(2026, 11, 4, 3, tzinfo=UTC)
    assert run_daily("nvd", trigger_time, trigger_time).source == "nvd"
    assert calls == [("nvd", datetime(2026, 11, 2, 3, tzinfo=UTC), trigger_time)]
    assert advanced == [trigger_time]


def test_backfill_modes_and_dates(monkeypatch):
    from threatflow.orchestration import ingestion_runner as runner

    calls = []

    def fake_execute(source, start=None, end=None, mode="modified", score_date=None):
        calls.append((source, start, end, mode, score_date))
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 1, 1, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    run_backfill("nvd", date(2025, 1, 1), date(2025, 1, 3), "published", 2)
    assert len(calls) == 2 and all(c[3] == "published" for c in calls)
    calls.clear()
    run_backfill("nvd", date(2025, 1, 1), date(2025, 1, 1), "modified")
    assert calls[0][3] == "modified"
    calls.clear()
    run_backfill("epss", date(2025, 1, 1), date(2025, 1, 3))
    assert [c[4] for c in calls] == [date(2025, 1, d) for d in (1, 2, 3)]


def test_cisa_backfill_runs_one_current_snapshot_sync(monkeypatch):
    from threatflow.orchestration import ingestion_runner as runner

    calls = []

    def fake_execute(source):
        calls.append(source)
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 20, 20, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)

    result = run_backfill("cisa", date(2025, 1, 1), date(2025, 1, 31))

    assert result.records_fetched == 20
    assert result.records_accepted == 20
    assert calls == ["cisa"]


def test_cisa_only_backfill_accepts_a_year_but_mixed_sources_do_not():
    validate_backfill(["cisa"], "2025-01-01", "2025-12-31")
    with pytest.raises(ValueError, match="invalid or excessive"):
        validate_backfill(["cisa", "nvd"], "2025-01-01", "2025-12-31")


def test_epss_backfill_skips_only_explicitly_missing_archive(monkeypatch, caplog):
    from threatflow.ingestion.epss_client import EpssArchiveNotFound
    from threatflow.orchestration import ingestion_runner as runner

    def fake_execute(source, start=None, end=None, mode="modified", score_date=None):
        if score_date == date(2021, 4, 22):
            raise EpssArchiveNotFound(score_date)
        now = datetime.now(UTC)
        return runner.IngestionResult(source, 1, 1, now, now)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    result = run_backfill("epss", date(2021, 4, 21), date(2021, 4, 23))

    assert result.records_fetched == 2
    assert result.missing_dates == 1
    assert "stage=archive_missing" in caplog.text
