"""Run one complete CISA KEV ingestion."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from threatflow.config import Settings
from threatflow.ingestion.cisa_client import CisaClient
from threatflow.ingestion.cisa_parser import parse_catalog
from threatflow.raw_storage import (
    RawArtifactStore,
    create_quarantine_artifact_store,
    create_raw_artifact_store,
)
from threatflow.s3_pipeline_state import S3PipelineState

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionResult:
    source: str
    acquired_at: datetime
    raw_artifact_path: str
    sha256: str
    downloaded_bytes: int
    parsed_records: int
    records_accepted: int
    bronze_object_created: bool


def ingest_cisa_kev(
    *,
    client: CisaClient | None = None,
    settings: Settings | None = None,
    raw_store: RawArtifactStore | None = None,
    quarantine_store: RawArtifactStore | None = None,
    state_store: S3PipelineState | None = None,
) -> IngestionResult:
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    if raw_store.backend != "s3":
        raise ValueError("CISA ingestion requires the S3 Bronze backend")
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
    try:
        records = parse_catalog(content)
        state_store = state_store or S3PipelineState.from_settings(settings)
        previous_count = state_store.latest_cisa_record_count()
        minimum = settings.cisa_minimum_record_count
        if previous_count is not None:
            minimum = max(
                minimum,
                int(previous_count * settings.cisa_minimum_previous_ratio),
            )
        if len(records) < minimum:
            raise ValueError(
                f"CISA KEV catalog is implausibly small: {len(records)} records; "
                f"minimum {minimum}, previous Silver count {previous_count}"
            )
    except ValueError:
        quarantine_store = quarantine_store or create_quarantine_artifact_store(settings)
        artifact = quarantine_store.store(
            "cisa_kev",
            content,
            acquired_at,
            ".json",
            metadata={
                "artifact-status": "quarantined",
                "failure-stage": "bronze-data-quality",
            },
        )
        LOGGER.exception("stage=bronze_quarantined source=cisa_kev uri=%s", artifact.uri)
        raise
    artifact = raw_store.store(
        "cisa_kev",
        content,
        acquired_at,
        ".json",
        metadata={
            "request-mode": "snapshot",
            "record-count": str(len(records)),
        },
    )
    result = IngestionResult(
        "cisa_kev",
        acquired_at,
        artifact.uri,
        artifact.sha256,
        len(content),
        len(records),
        len(records),
        artifact.created,
    )
    LOGGER.info("CISA KEV ingestion finished", extra=asdict(result))
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ingest_cisa_kev()
