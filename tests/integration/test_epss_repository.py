"""EPSS UPSERT behavior in an isolated PostgreSQL 17 container."""

import gzip
from datetime import date

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from testcontainers.core.docker_client import DockerClient
from testcontainers.postgres import PostgresContainer

from threatflow.config import Settings
from threatflow.ingestion import epss_ingestion
from threatflow.models.base import Base
from threatflow.models.epss import EpssCurrentScore, EpssDailySummary, EpssScore
from threatflow.repository.epss_repository import prune_history, upsert_records


def row(cve, day, score=0.1):
    return {"cve_id": cve, "score_date": day, "epss_score": score, "percentile": 0.5}


def require_docker():
    try:
        DockerClient().client.ping()
    except Exception as exc:
        pytest.skip(f"Docker daemon unavailable for isolated PostgreSQL test: {exc}")


@pytest.fixture
def session():
    require_docker()
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
    current = session.get(EpssCurrentScore, "CVE-2024-1234")
    assert (current.score_date, current.epss_score) == (b, 0.4)
    summary = session.get(EpssDailySummary, a)
    assert (summary.record_count, summary.high_risk_count) == (2, 1)


def test_current_does_not_regress_and_history_retention_is_inclusive(session):
    latest = date(2024, 2, 1)
    old = date(2024, 1, 1)
    cutoff = date(2024, 1, 3)
    upsert_records(session, [row("CVE-2024-1234", latest, 0.8)])
    upsert_records(session, [row("CVE-2024-1234", old, 0.1)])
    upsert_records(session, [row("CVE-2024-5678", cutoff, 0.2)])

    deleted = prune_history(session, latest_date=latest, retention_days=30)
    session.flush()

    assert deleted == 1
    assert session.get(EpssScore, ("CVE-2024-1234", old)) is None
    assert session.get(EpssScore, ("CVE-2024-5678", cutoff)) is not None
    current = session.get(EpssCurrentScore, "CVE-2024-1234")
    assert (current.score_date, current.epss_score) == (latest, 0.8)
    assert session.get(EpssDailySummary, old) is not None


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
    require_docker()
    monkeypatch.setattr(epss_ingestion, "validate_completeness", lambda *args: None)

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
