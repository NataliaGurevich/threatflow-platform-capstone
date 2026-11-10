"""Detect a new CISA KEV snapshot without replacing scheduled ingestion."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from threatflow.config import Settings
from threatflow.ingestion.cisa_client import CisaClient
from threatflow.ingestion.cisa_ingestion import IngestionResult, ingest_cisa_kev
from threatflow.models.raw_artifact import RawArtifact
from threatflow.raw_storage import (
    RawArtifactStore,
    calculate_sha256,
    create_raw_artifact_store,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class CisaArtifactObserved:
    """Pointer-only local event that can later be transported through a queue."""

    event_version: int
    source: str
    artifact_path: str
    sha256: str
    size_bytes: int
    acquired_at: datetime


@dataclass(frozen=True)
class CisaWatchResult:
    source: str
    checked_at: datetime
    sha256: str
    downloaded_bytes: int
    raw_artifact_path: str
    raw_artifact_created: bool
    changed: bool
    ingestion: IngestionResult | None


class _PrefetchedCisaClient:
    """Present already downloaded bytes to the existing ingestion service."""

    def __init__(self, content: bytes):
        self._content = content

    def fetch(self) -> bytes:
        return self._content


def _snapshot_exists(sha256: str, settings: Settings) -> bool:
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            return (
                session.scalar(
                    select(RawArtifact.id).where(
                        RawArtifact.source == "cisa_kev",
                        RawArtifact.request_mode == "snapshot",
                        RawArtifact.sha256 == sha256,
                    )
                )
                is not None
            )
    finally:
        engine.dispose()


def handle_cisa_artifact_observed(
    event: CisaArtifactObserved,
    *,
    settings: Settings | None = None,
    raw_artifact_created: bool = False,
    snapshot_exists: Callable[[str, Settings], bool] | None = None,
    ingest: Callable[..., IngestionResult] = ingest_cisa_kev,
    raw_store: RawArtifactStore | None = None,
) -> CisaWatchResult:
    """Compare an observed artifact and run normal ingestion only for a new hash."""
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    if event.event_version != 1 or event.source != "cisa_kev":
        raise ValueError("unsupported CISA artifact event")

    content = raw_store.read(event.artifact_path)
    if len(content) != event.size_bytes or calculate_sha256(content) != event.sha256:
        raise ValueError("CISA artifact does not match event metadata")

    exists = snapshot_exists or _snapshot_exists
    if exists(event.sha256, settings):
        LOGGER.info(
            "stage=cisa_watch_unchanged sha256=%s downloaded_bytes=%d path=%s",
            event.sha256,
            event.size_bytes,
            event.artifact_path,
        )
        return CisaWatchResult(
            event.source,
            event.acquired_at,
            event.sha256,
            event.size_bytes,
            event.artifact_path,
            raw_artifact_created,
            False,
            None,
        )

    LOGGER.info(
        "stage=cisa_watch_changed sha256=%s downloaded_bytes=%d path=%s",
        event.sha256,
        event.size_bytes,
        event.artifact_path,
    )
    result = ingest(client=_PrefetchedCisaClient(content), settings=settings)
    return CisaWatchResult(
        event.source,
        event.acquired_at,
        event.sha256,
        event.size_bytes,
        event.artifact_path,
        raw_artifact_created,
        True,
        result,
    )


def watch_cisa_kev(
    *,
    client: CisaClient | None = None,
    settings: Settings | None = None,
    snapshot_exists: Callable[[str, Settings], bool] | None = None,
    ingest: Callable[..., IngestionResult] = ingest_cisa_kev,
    raw_store: RawArtifactStore | None = None,
) -> CisaWatchResult:
    """Fetch and persist once, then deliver a local observation event.

    The daily CISA DAG remains the recovery path. Concurrent watcher and daily
    executions are safe because normal ingestion and repository writes are idempotent.
    """
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    client = client or CisaClient(
        connect_timeout=settings.http_connect_timeout,
        read_timeout=settings.http_read_timeout,
        retries=settings.http_retries,
    )
    checked_at = datetime.now(UTC)
    content = client.fetch()
    artifact = raw_store.store("cisa_kev", content, checked_at, ".json")
    event = CisaArtifactObserved(
        event_version=1,
        source="cisa_kev",
        artifact_path=artifact.uri,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        acquired_at=checked_at,
    )
    return handle_cisa_artifact_observed(
        event,
        settings=settings,
        raw_artifact_created=artifact.created,
        snapshot_exists=snapshot_exists,
        ingest=ingest,
        raw_store=raw_store,
    )


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    print(json.dumps(asdict(watch_cisa_kev()), default=str, sort_keys=True))


if __name__ == "__main__":
    main()
