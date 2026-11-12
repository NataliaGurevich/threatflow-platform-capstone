"""PostgreSQL 17 repository integration tests in disposable Testcontainers."""

import json
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from testcontainers.core.docker_client import DockerClient

pytest.importorskip("testcontainers.postgres")
from testcontainers.postgres import PostgresContainer

from threatflow.models.base import Base
from threatflow.models.cisa import CisaKevVulnerability
from threatflow.models.cisa_change import CisaKevChange
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef
from threatflow.raw_storage_reconciliation import list_reconciliation_candidates
from threatflow.repository.cisa_repository import upsert_records
from threatflow.repository.raw_artifact_repository import (
    artifact_location_uri,
    record_artifact,
    record_artifact_location,
)


def record(number: int, **changes):
    result = {
        "cve_id": f"CVE-2024-{number:04d}",
        "vendor_project": "Vendor",
        "product": "Product",
        "vulnerability_name": "Name",
        "date_added": date(2024, 1, 1),
        "short_description": "Description",
        "required_action": "Patch",
        "due_date": date(2024, 2, 1),
        "known_ransomware_campaign_use": "Unknown",
        "notes": None,
    }
    return result | changes


@pytest.fixture
def session():
    try:
        DockerClient().client.ping()
    except Exception as exc:
        pytest.skip(f"Docker daemon unavailable for isolated PostgreSQL test: {exc}")
    with PostgresContainer("postgres:17-alpine") as postgres:
        engine = create_engine(postgres.get_connection_url().replace("psycopg2", "psycopg"))
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as db:
                yield db
        finally:
            Base.metadata.drop_all(engine)
            engine.dispose()


def test_bulk_upsert_initial_idempotent_update_and_missing(session):
    assert upsert_records(session, [record(1), record(2)], batch_size=1) == (2, 0)
    session.flush()
    assert len(session.scalars(select(CisaKevVulnerability)).all()) == 2
    assert upsert_records(session, [record(1), record(2)]) == (0, 2)
    assert upsert_records(session, [record(1, product="Updated")]) == (0, 1)
    session.flush()
    assert session.get(CisaKevVulnerability, "CVE-2024-0001").product == "Updated"
    assert session.get(CisaKevVulnerability, "CVE-2024-0002") is not None
    assert len(session.scalars(select(CisaKevVulnerability)).all()) == 2


def test_transaction_rollback(session):
    # Enforce a failure on the second batch after the first batch has executed.
    session.execute(
        text(
            "ALTER TABLE cisa_kev_vulnerabilities "
            "ADD CONSTRAINT reject_bad_vendor CHECK (vendor_project <> 'FAIL')"
        )
    )
    session.commit()  # End the implicit transaction opened by the DDL statement.
    with pytest.raises(IntegrityError):
        with session.begin():
            upsert_records(session, [record(1), record(2, vendor_project="FAIL")], batch_size=1)
    session.rollback()
    assert session.scalars(select(CisaKevVulnerability)).all() == []


def test_raw_artifact_can_have_local_and_s3_locations(session):
    acquired_at = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
    digest = "a" * 64
    local = RawArtifactRef(
        source="cisa_kev",
        sha256=digest,
        uri="data/raw/cisa_kev/year=2026/month=11/artifact.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="local",
    )
    s3 = RawArtifactRef(
        source="cisa_kev",
        sha256=digest,
        uri=f"s3://threatflow-bronze/bronze/source=cisa_kev/sha256={digest}.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="s3",
        bucket="threatflow-bronze",
        object_key=f"bronze/source=cisa_kev/sha256={digest}.json",
        version_id="version-1",
    )

    record_artifact(session, local, acquired_at, request_mode="snapshot")
    session.flush()
    artifact = session.scalar(select(RawArtifact).where(RawArtifact.sha256 == digest))
    candidates = list_reconciliation_candidates(session, "cisa_kev")
    assert [candidate.artifact_id for candidate in candidates] == [artifact.id]
    record_artifact_location(session, artifact.id, s3, acquired_at)
    session.flush()
    assert list_reconciliation_candidates(session, "cisa_kev") == []
    session.expire_all()

    artifact = session.scalar(select(RawArtifact).where(RawArtifact.sha256 == digest))
    locations = session.scalars(
        select(RawArtifactLocation)
        .where(RawArtifactLocation.artifact_id == artifact.id)
        .order_by(RawArtifactLocation.backend)
    ).all()

    assert artifact.storage_path == local.uri
    assert artifact.seen_count == 1
    assert [(location.backend, location.uri) for location in locations] == [
        ("local", local.uri),
        ("s3", s3.uri),
    ]
    assert artifact_location_uri(artifact, "local") == local.uri
    assert artifact_location_uri(artifact, "s3") == s3.uri
    assert locations[1].storage_version_id == "version-1"


def test_reconciliation_excludes_invalid_cisa_git_snapshots(session):
    acquired_at = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
    valid = RawArtifactRef(
        source="cisa_kev",
        sha256="d" * 64,
        uri="data/raw/cisa_kev/valid.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="local",
    )
    invalid = RawArtifactRef(
        source="cisa_kev",
        sha256="e" * 64,
        uri="data/raw/cisa_kev/invalid.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="local",
    )
    record_artifact(session, valid, acquired_at, request_mode="git_history")
    record_artifact(session, invalid, acquired_at, request_mode="git_history_invalid")
    session.flush()

    candidates = list_reconciliation_candidates(session, "cisa_kev")

    assert [candidate.sha256 for candidate in candidates] == [valid.sha256]


def test_one_observation_records_local_and_s3_locations_without_double_counting(session):
    acquired_at = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
    digest = "c" * 64
    local = RawArtifactRef(
        source="nvd",
        sha256=digest,
        uri="data/raw/nvd/artifact.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="local",
    )
    s3 = RawArtifactRef(
        source="nvd",
        sha256=digest,
        uri=f"s3://threatflow-bronze/bronze/source=nvd/sha256={digest}.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="s3",
        bucket="threatflow-bronze",
        object_key=f"bronze/source=nvd/sha256={digest}.json",
        version_id="version-2",
    )

    record_artifact(session, local, acquired_at, additional_locations=(s3,))
    session.flush()
    artifact = session.scalar(select(RawArtifact).where(RawArtifact.sha256 == digest))
    locations = session.scalars(
        select(RawArtifactLocation)
        .where(RawArtifactLocation.artifact_id == artifact.id)
        .order_by(RawArtifactLocation.backend)
    ).all()

    assert artifact.seen_count == 1
    assert [(location.backend, location.uri) for location in locations] == [
        ("local", local.uri),
        ("s3", s3.uri),
    ]


def test_s3_location_requires_structured_bucket_and_key(session):
    acquired_at = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
    local = RawArtifactRef(
        source="cisa_kev",
        sha256="b" * 64,
        uri="data/raw/cisa_kev/artifact.json",
        extension="json",
        content_type="application/json",
        size_bytes=42,
        created=True,
        backend="local",
    )
    record_artifact(session, local, acquired_at)
    session.flush()
    artifact = session.scalar(select(RawArtifact).where(RawArtifact.sha256 == local.sha256))
    session.add(
        RawArtifactLocation(
            artifact_id=artifact.id,
            backend="s3",
            uri="s3://missing-structured-fields/object.json",
            first_recorded_at=acquired_at,
            last_verified_at=acquired_at,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_reconciliation_dry_run_uses_manifest_and_local_bytes_without_aws(
    session, tmp_path, monkeypatch
):
    from threatflow import raw_storage_reconciliation
    from threatflow.config import Settings
    from threatflow.local_raw_storage import LocalRawArtifactStore

    acquired_at = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
    local_store = LocalRawArtifactStore(tmp_path)
    local = local_store.store("epss", b"compressed-csv", acquired_at, "csv.gz")
    record_artifact(session, local, acquired_at, request_mode="historical")
    session.commit()

    engine = session.get_bind()
    monkeypatch.setattr(raw_storage_reconciliation, "create_engine", lambda _: engine)

    def reject_aws_client(*args, **kwargs):
        raise AssertionError("dry-run must not create an AWS client")

    monkeypatch.setattr("threatflow.s3_raw_storage.boto3.client", reject_aws_client)
    result = raw_storage_reconciliation.reconcile_raw_storage(
        Settings(
            raw_data_dir=str(tmp_path),
            s3_bronze_bucket="threatflow-bronze",
            _env_file=None,
        ),
        source="epss",
        dry_run=True,
    )

    assert result.scanned == result.verified == result.planned == 1
    assert result.uploaded == result.reused == 0
    assert result.target_uris == (
        f"s3://threatflow-bronze/bronze/source=epss/sha256={local.sha256}.csv.gz",
    )


def test_daily_ingestion_writes_incremental_changes_atomically(session, tmp_path, monkeypatch):
    from threatflow.config import Settings
    from threatflow.ingestion import cisa_ingestion

    def snapshot(product="Product", *, include_second=False):
        vulnerabilities = [
            {
                "cveID": "CVE-2024-0001",
                "vendorProject": "Vendor",
                "product": product,
                "vulnerabilityName": "Name",
                "dateAdded": "2024-01-01",
                "shortDescription": "Description",
                "requiredAction": "Patch",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ]
        if include_second:
            vulnerabilities.append(
                vulnerabilities[0] | {"cveID": "CVE-2024-0002", "vulnerabilityName": "Second"}
            )
        return json.dumps(
            {"count": len(vulnerabilities), "vulnerabilities": vulnerabilities}
        ).encode()

    class Client:
        content = snapshot()

        def fetch(self):
            return self.content

    client = Client()
    engine = session.get_bind()
    monkeypatch.setattr(cisa_ingestion, "create_engine", lambda _: engine)
    settings = Settings(raw_data_dir=str(tmp_path), database_url="unused", _env_file=None)

    first = cisa_ingestion.ingest_cisa_kev(client=client, settings=settings)
    client.content = snapshot("Updated", include_second=True)
    second = cisa_ingestion.ingest_cisa_kev(client=client, settings=settings)
    repeated = cisa_ingestion.ingest_cisa_kev(client=client, settings=settings)

    session.expire_all()
    changes = session.scalars(
        select(CisaKevChange).order_by(CisaKevChange.committed_at, CisaKevChange.cve_id)
    ).all()
    assert first.change_records == 1
    assert second.change_records == 2
    assert repeated.change_records == 0
    assert [change.change_type for change in changes] == ["baseline", "modified", "added"]
    assert changes[1].changed_fields == ["product"]
    assert all(change.revision_type == "content_sha256" for change in changes)
