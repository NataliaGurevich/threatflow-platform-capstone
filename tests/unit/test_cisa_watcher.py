from datetime import UTC, datetime
from pathlib import Path

import pytest

from threatflow.config import Settings
from threatflow.ingestion.cisa_ingestion import IngestionResult
from threatflow.ingestion.cisa_watcher import (
    CisaArtifactObserved,
    handle_cisa_artifact_observed,
    watch_cisa_kev,
)
from threatflow.raw_storage import calculate_sha256


class Client:
    def __init__(self, content: bytes):
        self.content = content

    def fetch(self) -> bytes:
        return self.content


def test_unchanged_snapshot_is_stored_locally_and_does_not_run_ingestion(tmp_path):
    content = b'{"count": 1, "vulnerabilities": []}'

    def fail_ingestion(**kwargs):
        raise AssertionError("unchanged content must not run ingestion")

    result = watch_cisa_kev(
        client=Client(content),
        settings=Settings(raw_data_dir=str(tmp_path)),
        snapshot_exists=lambda digest, settings: digest == calculate_sha256(content),
        ingest=fail_ingestion,
    )

    assert result.changed is False
    assert result.ingestion is None
    assert result.sha256 == calculate_sha256(content)
    assert result.downloaded_bytes == len(content)
    assert result.raw_artifact_created is True
    assert tmp_path in Path(result.raw_artifact_path).parents


def test_new_snapshot_reuses_locally_stored_bytes_in_existing_ingestion(tmp_path):
    content = b'{"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-1"}]}'
    captured = {}
    ingested = IngestionResult(
        source="cisa_kev",
        acquired_at=datetime(2026, 11, 9, tzinfo=UTC),
        raw_artifact_path="data/raw/cisa.json",
        sha256=calculate_sha256(content),
        downloaded_bytes=len(content),
        parsed_records=1,
        inserted_records=1,
        updated_records=0,
        change_records=1,
    )

    def ingest(*, client, settings):
        captured["content"] = client.fetch()
        captured["settings"] = settings
        return ingested

    settings = Settings(raw_data_dir=str(tmp_path))
    result = watch_cisa_kev(
        client=Client(content),
        settings=settings,
        snapshot_exists=lambda digest, current_settings: False,
        ingest=ingest,
    )

    assert result.changed is True
    assert result.ingestion == ingested
    assert captured == {"content": content, "settings": settings}
    assert result.raw_artifact_created is True
    assert len(list(tmp_path.rglob("*.json"))) == 1


def test_new_invalid_snapshot_propagates_ingestion_failure_but_keeps_raw(tmp_path):
    def reject(**kwargs):
        raise ValueError("invalid CISA KEV catalog")

    with pytest.raises(ValueError, match="invalid CISA"):
        watch_cisa_kev(
            client=Client(b"invalid"),
            settings=Settings(raw_data_dir=str(tmp_path)),
            snapshot_exists=lambda digest, settings: False,
            ingest=reject,
        )
    assert len(list(tmp_path.rglob("*.json"))) == 1


def test_handler_rejects_artifact_that_does_not_match_event(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_bytes(b"actual")
    event = CisaArtifactObserved(
        event_version=1,
        source="cisa_kev",
        artifact_path=str(path),
        sha256=calculate_sha256(b"different"),
        size_bytes=len(b"actual"),
        acquired_at=datetime(2026, 11, 10, tzinfo=UTC),
    )

    with pytest.raises(ValueError, match="does not match"):
        handle_cisa_artifact_observed(event, settings=Settings(raw_data_dir=str(tmp_path)))
