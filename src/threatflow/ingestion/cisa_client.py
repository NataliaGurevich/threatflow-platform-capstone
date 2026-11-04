"""HTTP client for the official CISA KEV catalog."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime
from datetime import time as datetime_time

import httpx

LOGGER = logging.getLogger(__name__)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_COMMITS_URL = "https://api.github.com/repos/cisagov/kev-data/commits"
GITHUB_RAW_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/{revision}/"
    "known_exploited_vulnerabilities.json"
)


@dataclass(frozen=True)
class CisaGitCommit:
    sha: str
    committed_at: datetime


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


class CisaGitHistoryClient:
    """Read official KEV file revisions from the CISA GitHub mirror."""

    def __init__(
        self,
        *,
        token: str | None = None,
        connect_timeout: float = 10,
        read_timeout: float = 60,
        retries: int = 3,
    ):
        self.timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self.retries = retries
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _get(self, url: str, **kwargs) -> httpx.Response:
        for attempt in range(self.retries + 1):
            try:
                response = httpx.get(url, timeout=self.timeout, headers=self.headers, **kwargs)
                response.raise_for_status()
                return response
            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPStatusError) as exc:
                transient = not isinstance(
                    exc, httpx.HTTPStatusError
                ) or exc.response.status_code in {408, 429, 500, 502, 503, 504}
                if not transient or attempt >= self.retries:
                    raise
                LOGGER.warning("CISA Git history request attempt %d failed; retrying", attempt + 1)
                time.sleep(min(2**attempt, 8))
        raise RuntimeError("unreachable")

    def list_commits(self, start: date, end: date) -> list[CisaGitCommit]:
        if start > end:
            raise ValueError("CISA history start must not be after end")
        since = datetime.combine(start, datetime_time.min, UTC)
        until = datetime.combine(end, datetime_time.max, UTC)
        commits: list[CisaGitCommit] = []
        page = 1
        while True:
            response = self._get(
                GITHUB_COMMITS_URL,
                params={
                    "path": "known_exploited_vulnerabilities.json",
                    "since": since.isoformat(),
                    "until": until.isoformat(),
                    "per_page": 100,
                    "page": page,
                },
            )
            payload = response.json()
            if not isinstance(payload, list):
                raise ValueError("invalid CISA GitHub commit response")
            for item in payload:
                try:
                    sha = item["sha"]
                    timestamp = item["commit"]["committer"]["date"]
                    committed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except (KeyError, TypeError, ValueError, AttributeError) as exc:
                    raise ValueError("invalid CISA GitHub commit metadata") from exc
                if not isinstance(sha, str) or len(sha) != 40 or committed_at.tzinfo is None:
                    raise ValueError("invalid CISA GitHub commit metadata")
                commits.append(CisaGitCommit(sha, committed_at.astimezone(UTC)))
            if len(payload) < 100:
                break
            page += 1
        return sorted(commits, key=lambda commit: (commit.committed_at, commit.sha))

    def fetch_snapshot(self, revision: str) -> bytes:
        if len(revision) != 40 or any(
            character not in "0123456789abcdef" for character in revision
        ):
            raise ValueError("invalid CISA Git revision")
        return self._get(GITHUB_RAW_URL.format(revision=revision)).content
