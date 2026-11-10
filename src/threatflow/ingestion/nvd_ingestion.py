"""Incremental NVD current-state ingestion orchestration."""

from __future__ import annotations

import logging
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine

from threatflow.config import Settings
from threatflow.ingestion.nvd_client import NvdClient
from threatflow.ingestion.nvd_parser import parse_response
from threatflow.raw_storage import RawArtifactStore, create_raw_artifact_store
from threatflow.repository.nvd_repository import upsert_records
from threatflow.repository.raw_artifact_repository import record_artifact

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class NvdIngestionResult:
    source: str
    requested_start: datetime
    requested_end: datetime
    acquired_at: datetime
    pages_retrieved: int
    downloaded_bytes: int
    raw_artifacts: tuple[str, ...]
    total_records_received: int
    unique_records_processed: int
    inserted_records: int
    updated_records: int
    rejected_count: int


def _deduplicate(records: list[dict]) -> list[dict]:
    selected: dict[str, dict] = {}
    for record in records:
        prior = selected.get(record["cve_id"])
        if prior is None or record["last_modified"] > prior["last_modified"]:
            selected[record["cve_id"]] = record
        elif record["last_modified"] == prior["last_modified"] and record != prior:
            raise ValueError(
                f"conflicting duplicate CVE {record['cve_id']} with equal lastModified"
            )
    return [selected[key] for key in sorted(selected)]


def ingest_nvd_cves(
    *,
    client: NvdClient | None = None,
    settings: Settings | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    mode: str = "modified",
    raw_store: RawArtifactStore | None = None,
) -> NvdIngestionResult:
    if mode not in {"modified", "published"}:
        raise ValueError("NVD mode must be modified or published")
    settings = settings or Settings()
    raw_store = raw_store or create_raw_artifact_store(settings)
    acquired_at = datetime.now(UTC)
    end = end or acquired_at
    start = start or end - timedelta(hours=settings.nvd_modified_lookback_hours)
    if (
        start.tzinfo is None
        or end.tzinfo is None
        or start >= end
        or end - start > timedelta(days=120)
    ):
        raise ValueError("invalid NVD modification date window")
    LOGGER.info(
        "NVD ingestion started",
        extra={"source": "nvd", "start": start.isoformat(), "end": end.isoformat()},
    )
    if client is None:
        key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
        client = NvdClient(
            base_url=settings.nvd_api_base_url,
            api_key=key,
            page_size=settings.nvd_page_size,
            connect_timeout=settings.http_connect_timeout,
            read_timeout=settings.http_read_timeout,
            retries=settings.http_retries,
        )
    artifacts, artifact_pages, records = [], [], []
    total_bytes = total_received = 0
    index = 0
    expected_total = None
    page_number = 0
    while True:
        page_number += 1
        content = (
            client.fetch_page(start, end, index)
            if mode == "modified"
            else client.fetch_page(start, end, index, mode=mode)
        )
        artifact = raw_store.store("nvd", content, acquired_at, ".json")
        artifacts.append(artifact.uri)
        total_bytes += len(content)
        LOGGER.info(
            "NVD page stored",
            extra={"page": page_number, "bytes": len(content), "sha256": artifact.sha256},
        )
        meta, page_records = parse_response(content)
        artifact_pages.append((artifact, index, len(page_records)))
        if meta["startIndex"] != index or meta["resultsPerPage"] != len(page_records):
            raise ValueError("NVD pagination metadata does not match requested page")
        if expected_total is None:
            expected_total = meta["totalResults"]
        elif expected_total != meta["totalResults"]:
            raise ValueError("NVD totalResults changed during pagination")
        total_received += len(page_records)
        records.extend(page_records)
        LOGGER.info(
            "NVD page parsed",
            extra={
                "page": page_number,
                "total_results": expected_total,
                "records": len(page_records),
            },
        )
        if index + len(page_records) >= expected_total:
            if index + len(page_records) != expected_total:
                raise ValueError("NVD pagination exceeded totalResults")
            break
        if not page_records or len(page_records) > settings.nvd_page_size:
            raise ValueError("NVD pagination made no progress or exceeded page size")
        index += len(page_records)
        if page_number > expected_total + 1:
            raise ValueError("NVD pagination safety limit exceeded")
    unique = _deduplicate(records)
    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            from sqlalchemy.orm import Session

            with Session(bind=connection) as session:
                for artifact, page_start_index, record_count in artifact_pages:
                    record_artifact(
                        session,
                        artifact,
                        acquired_at,
                        request_mode=mode,
                        requested_start=start,
                        requested_end=end,
                        page_start_index=page_start_index,
                        record_count=record_count,
                        ingestion_run_id=os.getenv("AIRFLOW_CTX_DAG_RUN_ID"),
                    )
                inserted, updated = upsert_records(session, unique)
                session.flush()
    finally:
        engine.dispose()
    result = NvdIngestionResult(
        "nvd",
        start,
        end,
        acquired_at,
        page_number,
        total_bytes,
        tuple(artifacts),
        total_received,
        len(unique),
        inserted,
        updated,
        0,
    )
    LOGGER.info("NVD ingestion finished", extra=asdict(result))
    return result


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ingest_nvd_cves()
