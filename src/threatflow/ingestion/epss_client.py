"""HTTP client for official current and historical EPSS gzip CSV datasets."""

from __future__ import annotations

import email.utils
import time
from datetime import UTC, date, datetime

import httpx

CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
ARCHIVE_URL = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/{year}/epss_scores-{date}.csv.gz"
RETRYABLE = {408, 429, 500, 502, 503, 504}


class EpssClient:
    def __init__(
        self,
        *,
        connect_timeout: float = 10,
        read_timeout: float = 120,
        retries: int = 3,
        sleep=time.sleep,
    ):
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.retries = retries
        self.sleep = sleep

    def fetch(self, score_date: date | None = None) -> bytes:
        """Return exact downloaded bytes; historical dates resolve to archive identity."""
        if score_date is not None and score_date < date(2021, 4, 14):
            raise ValueError("EPSS historical scores are unavailable before 2021-04-14")
        url = (
            CURRENT_URL
            if score_date is None
            else ARCHIVE_URL.format(year=score_date.year, date=score_date.isoformat())
        )
        for attempt in range(self.retries + 1):
            try:
                response = httpx.get(url, timeout=self.timeout, follow_redirects=True)
                response.raise_for_status()
                return response.content
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                status = (
                    exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                )
                if (status is not None and status not in RETRYABLE) or attempt >= self.retries:
                    raise
                delay = min(2**attempt, 30)
                if status == 429:
                    raw = exc.response.headers.get("Retry-After")
                    if raw:
                        try:
                            delay = max(0, float(raw))
                        except ValueError:
                            try:
                                delay = max(
                                    0,
                                    (
                                        email.utils.parsedate_to_datetime(raw) - datetime.now(UTC)
                                    ).total_seconds(),
                                )
                            except (TypeError, ValueError, OverflowError):
                                pass
                self.sleep(delay)
        raise RuntimeError("unreachable")
