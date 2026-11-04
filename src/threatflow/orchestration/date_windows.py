"""Deterministic UTC windows. API endpoints are inclusive, so adjacent chunks share 1 ms."""

from datetime import UTC, date, datetime, time, timedelta


def utc_day(day: date) -> tuple[datetime, datetime]:
    start = datetime.combine(day, time.min, UTC)
    return start, start + timedelta(days=1) - timedelta(milliseconds=1)


def date_chunks(start: date, end: date, days: int):
    if start > end or days < 1:
        raise ValueError("invalid date range or chunk size")
    cursor = start
    while cursor <= end:
        last = min(end, cursor + timedelta(days=days - 1))
        yield cursor, last
        cursor = last + timedelta(days=1)


def nvd_daily_window(interval_end: datetime, lookback_hours: int = 48):
    if interval_end.tzinfo is None or not 1 <= lookback_hours <= 24 * 120:
        raise ValueError("invalid NVD daily window")
    end = interval_end.astimezone(UTC)
    return end - timedelta(hours=lookback_hours), end


def nvd_recovery_window(
    interval_end: datetime, lookback_hours: int, covered_until: datetime | None
):
    start, end = nvd_daily_window(interval_end, lookback_hours)
    if covered_until is not None:
        if covered_until.tzinfo is None:
            raise ValueError("checkpoint must be timezone aware")
        start = min(start, covered_until.astimezone(UTC))
    return start, end
