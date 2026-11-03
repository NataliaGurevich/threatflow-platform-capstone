"""PostgreSQL 17 repository integration tests using isolated Testcontainers."""

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from testcontainers.core.docker_client import DockerClient

pytest.importorskip("testcontainers.postgres")
from testcontainers.postgres import PostgresContainer

from threatflow.models.base import Base
from threatflow.models.nvd import NvdCve
from threatflow.repository.nvd_repository import upsert_records


def record(number, **changes):
    return {
        "cve_id": f"CVE-2024-{number:04d}",
        "description": "desc",
        "published": None,
        "last_modified": None,
        "cvss_version": None,
        "cvss_score": None,
        "cvss_severity": None,
        "cvss_vector": None,
        "cwe_ids": None,
        "references": None,
    } | changes


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


def test_insert_idempotent_update_optional_fields_batch_and_retention(session):
    assert upsert_records(session, [record(1), record(2)], batch_size=1) == (2, 0)
    session.flush()
    assert upsert_records(session, [record(1), record(2)]) == (0, 2)
    assert upsert_records(session, [record(1, description="updated")]) == (0, 1)
    session.flush()
    assert session.get(NvdCve, "CVE-2024-0001").description == "updated"
    assert session.get(NvdCve, "CVE-2024-0002") is not None


def test_older_record_cannot_replace_newer_record(session):
    from datetime import UTC, datetime

    newer = datetime(2024, 2, 1, tzinfo=UTC)
    older = datetime(2024, 1, 1, tzinfo=UTC)
    assert upsert_records(session, [record(1, description="new", last_modified=newer)]) == (1, 0)
    assert upsert_records(session, [record(1, description="old", last_modified=older)]) == (0, 0)
    session.flush()
    assert session.get(NvdCve, "CVE-2024-0001").description == "new"


def test_transaction_rollback(session):
    session.execute(
        text("ALTER TABLE nvd_cves ADD CONSTRAINT reject_bad CHECK (description <> 'FAIL')")
    )
    session.commit()
    with pytest.raises(IntegrityError):
        with session.begin():
            upsert_records(session, [record(1), record(2, description="FAIL")], batch_size=1)
    session.rollback()
    assert session.scalars(select(NvdCve)).all() == []
