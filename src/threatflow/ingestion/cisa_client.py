"""HTTP client for the official CISA KEV catalog."""

from __future__ import annotations

import logging
import time

import httpx

LOGGER = logging.getLogger(__name__)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaClient:
    def __init__(self, *, connect_timeout: float = 10, read_timeout: float = 30, retries: int = 3):
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.retries = retries

    def fetch(self) -> bytes:
        for attempt in range(self.retries + 1):
            try:
                response = httpx.get(CISA_KEV_URL, timeout=self.timeout)
                response.raise_for_status()
                return response.content
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                transient = not isinstance(
                    exc, httpx.HTTPStatusError
                ) or exc.response.status_code in {408, 429, 500, 502, 503, 504}
                if not transient or attempt >= self.retries:
                    raise
                LOGGER.warning("CISA request attempt %d failed; retrying", attempt + 1)
                time.sleep(min(2**attempt, 8))
        raise RuntimeError("unreachable")
