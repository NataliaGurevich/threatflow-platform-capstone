"""PostgreSQL 17 repository integration tests in disposable Testcontainers."""

import json
from datetime import date

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
from threatflow.repository.cisa_repository import upsert_records


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
    settings = Settings(raw_data_dir=str(tmp_path), database_url="unused")

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
