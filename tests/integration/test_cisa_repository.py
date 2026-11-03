"""PostgreSQL 17 repository integration tests in disposable Testcontainers."""

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
