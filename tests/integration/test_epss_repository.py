"""EPSS UPSERT behavior in an isolated PostgreSQL 17 container."""

from datetime import date

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from testcontainers.core.docker_client import DockerClient
from testcontainers.postgres import PostgresContainer

from threatflow.models.base import Base
from threatflow.models.epss import EpssCurrentScore, EpssDailySummary, EpssScore
from threatflow.repository.epss_repository import prune_history, upsert_records, upsert_summary


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


def test_summary_can_be_written_without_detail_rows(session):
    day = date(2021, 4, 14)
    upsert_summary(
        session,
        [
            row("CVE-2021-0001", day, 0.05),
            row("CVE-2021-0002", day, 0.2),
            row("CVE-2021-0003", day, 0.8),
        ],
    )
    session.flush()

    assert session.scalars(select(EpssScore)).all() == []
    summary = session.get(EpssDailySummary, day)
    assert summary.record_count == 3
    assert summary.average_score == pytest.approx(0.35)
    assert (summary.low_risk_count, summary.medium_risk_count, summary.high_risk_count) == (1, 1, 1)


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
