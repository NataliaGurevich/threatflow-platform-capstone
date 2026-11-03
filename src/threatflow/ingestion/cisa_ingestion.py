"""Run one complete CISA KEV ingestion."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from sqlalchemy import create_engine

from threatflow.config import Settings
from threatflow.ingestion.cisa_client import CisaClient
from threatflow.ingestion.cisa_parser import parse_catalog
from threatflow.raw_storage import store_raw_artifact
from threatflow.repository.cisa_repository import upsert_records

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestionResult:
    source: str
    acquired_at: datetime
    raw_artifact_path: str
    sha256: str
    downloaded_bytes: int
    parsed_records: int
    inserted_records: int
    updated_records: int


def ingest_cisa_kev(
    *, client: CisaClient | None = None, settings: Settings | None = None
) -> IngestionResult:
    settings = settings or Settings()
    acquired_at = datetime.now(UTC)
    LOGGER.info("CISA KEV ingestion started", extra={"source": "cisa_kev"})
    content = (client or CisaClient()).fetch()
    artifact = store_raw_artifact(
        "cisa_kev", content, acquired_at, ".json", raw_data_dir=settings.raw_data_dir
    )
    records = parse_catalog(content)
    engine = create_engine(settings.database_url)
    try:
        with engine.begin() as connection:
            from sqlalchemy.orm import Session

            with Session(bind=connection) as session:
                inserted, updated = upsert_records(session, records)
                session.flush()
        result = IngestionResult(
            "cisa_kev",
            acquired_at,
            str(artifact.path),
            artifact.sha256,
            len(content),
            len(records),
            inserted,
            updated,
        )
        LOGGER.info("CISA KEV ingestion finished", extra=asdict(result))
        return result
    finally:
        engine.dispose()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ingest_cisa_kev()
