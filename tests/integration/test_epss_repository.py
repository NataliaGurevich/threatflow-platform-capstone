"""EPSS UPSERT behavior in an isolated PostgreSQL 17 container."""

from datetime import date
import gzip

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from testcontainers.postgres import PostgresContainer

from threatflow.models.base import Base
from threatflow.models.epss import EpssScore
from threatflow.repository.epss_repository import upsert_records
from threatflow.config import Settings
from threatflow.ingestion import epss_ingestion


def row(cve, day, score=0.1):
    return {"cve_id": cve, "score_date": day, "epss_score": score, "percentile": 0.5}


@pytest.fixture
def session():
    with PostgresContainer("postgres:17-alpine") as postgres:
        engine = create_engine(postgres.get_connection_url().replace("psycopg2", "psycopg"))
        Base.metadata.create_all(engine)
        try:
            with Session(engine) as db:
                yield db
        finally:
            engine.dispose()


def test_insert_repeat_update_dates_batch_and_retention(session):
    a, b = date(2024, 1, 1), date(2024, 1, 2)
    first = row("CVE-2024-1234", a)
    other = row("CVE-2024-5678", a)
    assert upsert_records(session, [first, other], batch_size=1) == (2, 0)
    assert upsert_records(session, [first], batch_size=1) == (0, 1)
    assert upsert_records(session, [row("CVE-2024-1234", a, 0.9)]) == (0, 1)
    assert upsert_records(session, [row("CVE-2024-1234", b, 0.4)]) == (1, 0)
    session.flush()
    assert session.get(EpssScore, ("CVE-2024-1234", a)).epss_score == 0.9
    assert session.get(EpssScore, ("CVE-2024-1234", b)).epss_score == 0.4
    assert session.get(EpssScore, ("CVE-2024-5678", a)) is not None
    assert len(session.scalars(select(EpssScore)).all()) == 3


def test_rollback_across_batches(session):
    session.execute(
        text("ALTER TABLE epss_scores ADD CONSTRAINT reject_score CHECK (epss_score < 0.8)")
    )
    session.commit()
    with pytest.raises(IntegrityError):
        with session.begin():
            upsert_records(
                session,
                [
                    row("CVE-2024-1234", date(2024, 1, 1)),
                    row("CVE-2024-5678", date(2024, 1, 1), 0.9),
                ],
                batch_size=1,
            )
    session.rollback()
    assert session.scalars(select(EpssScore)).all() == []


def test_ingestion_service_current_and_historical_in_isolated_postgres(monkeypatch, tmp_path):
    class Client:
        def fetch(self, score_date):
            day = score_date or date(2024, 1, 2)
            csv = (
                f"#model_version:v1,score_date:{day.isoformat()}T00:00:00Z\n"
                "cve,epss,percentile\nCVE-2024-1234,0.1,0.5\n"
            )
            return gzip.compress(csv.encode())

    with PostgresContainer("postgres:17-alpine") as postgres:
        engine = create_engine(postgres.get_connection_url().replace("psycopg2", "psycopg"))
        Base.metadata.create_all(engine)
        monkeypatch.setattr(epss_ingestion, "create_engine", lambda _: engine)
        settings = Settings(raw_data_dir=str(tmp_path))
        current = epss_ingestion.ingest_epss(client=Client(), settings=settings)
        historic = epss_ingestion.ingest_epss(
            client=Client(), settings=settings, score_date=date(2024, 1, 1)
        )
        assert current.score_date == date(2024, 1, 2)
        assert historic.score_date == date(2024, 1, 1)
        assert current.inserted_records == historic.inserted_records == 1
        assert len(list(tmp_path.rglob("*.csv.gz"))) == 2
        with Session(engine) as db:
            assert len(db.scalars(select(EpssScore)).all()) == 2
        engine.dispose()
