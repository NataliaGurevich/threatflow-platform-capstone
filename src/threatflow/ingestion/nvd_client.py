"""HTTP client for NVD CVE API 2.0 with bounded retries and pacing."""

from __future__ import annotations

import email.utils
import logging
import time
from datetime import UTC, datetime

import httpx

LOGGER = logging.getLogger(__name__)
RETRYABLE = {408, 429, 500, 502, 503, 504}


class NvdClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        page_size: int = 2000,
        connect_timeout: float = 10,
        read_timeout: float = 60,
        retries: int = 3,
        min_interval: float = 6,
        sleep=time.sleep,
    ):
        if not 1 <= page_size <= 2000:
            raise ValueError("NVD page size must be between 1 and 2000")
        self.base_url, self.page_size, self.retries, self.min_interval = (
            base_url,
            page_size,
            retries,
            min_interval,
        )
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.headers = {"apiKey": api_key} if api_key else {}
        self.sleep = sleep
        self._last_request = 0.0

    def fetch_page(
        self, start: datetime, end: datetime, start_index: int, mode: str = "modified"
    ) -> bytes:
        if mode not in {"modified", "published"}:
            raise ValueError("NVD mode must be modified or published")
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError("date window must be timezone-aware and start before end")
        if (end - start).total_seconds() > 120 * 86400:
            raise ValueError("NVD modification window cannot exceed 120 days")
        prefix = "lastMod" if mode == "modified" else "pub"
        params = {
            f"{prefix}StartDate": start.astimezone(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            f"{prefix}EndDate": end.astimezone(UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "startIndex": start_index,
            "resultsPerPage": self.page_size,
        }
        for attempt in range(self.retries + 1):
            delay = self.min_interval - (time.monotonic() - self._last_request)
            if delay > 0:
                self.sleep(delay)
            try:
                response = httpx.get(
                    self.base_url, params=params, headers=self.headers, timeout=self.timeout
                )
                self._last_request = time.monotonic()
                response.raise_for_status()
                return response.content
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                status = (
                    exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
                )
                if status is not None and status not in RETRYABLE or attempt >= self.retries:
                    raise
                retry_after = None
                if status == 429 and isinstance(exc, httpx.HTTPStatusError):
                    raw = exc.response.headers.get("Retry-After")
                    if raw:
                        try:
                            retry_after = max(0.0, float(raw))
                        except ValueError:
                            try:
                                retry_after = max(
                                    0.0,
                                    (
                                        email.utils.parsedate_to_datetime(raw) - datetime.now(UTC)
                                    ).total_seconds(),
                                )
                            except (TypeError, ValueError, OverflowError):
                                pass
                wait = retry_after if retry_after is not None else min(2**attempt, 30)
                LOGGER.warning(
                    "NVD request failed; retrying",
                    extra={"attempt": attempt + 1, "status": status, "wait_seconds": wait},
                )
                self.sleep(wait)
        raise RuntimeError("unreachable")
