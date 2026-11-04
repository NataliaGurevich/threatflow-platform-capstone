"""PostgreSQL persistence and retention for EPSS scores."""

from datetime import date, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.epss import EpssCurrentScore, EpssDailySummary, EpssScore


def upsert_records(
    session: Session, records: list[dict], *, batch_size: int = 1000
) -> tuple[int, int]:
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    inserted = updated = 0
    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        existing = set()
        for score_date in {record["score_date"] for record in batch}:
            ids = [record["cve_id"] for record in batch if record["score_date"] == score_date]
            existing.update(
                (cve_id, score_date)
                for cve_id in session.scalars(
                    select(EpssScore.cve_id).where(
                        EpssScore.score_date == score_date, EpssScore.cve_id.in_(ids)
                    )
                )
            )
        stmt = insert(EpssScore).values(batch)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[EpssScore.cve_id, EpssScore.score_date],
                set_={
                    "epss_score": stmt.excluded.epss_score,
                    "percentile": stmt.excluded.percentile,
                    "updated_at": func.now(),
                },
            )
        )
        updated += len(existing)
        inserted += len(batch) - len(existing)
    _upsert_current(session, records, batch_size)
    _upsert_summary(session, records)
    return inserted, updated


def _upsert_current(session: Session, records: list[dict], batch_size: int) -> None:
    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        stmt = insert(EpssCurrentScore).values(batch)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[EpssCurrentScore.cve_id],
                set_={
                    "score_date": stmt.excluded.score_date,
                    "epss_score": stmt.excluded.epss_score,
                    "percentile": stmt.excluded.percentile,
                    "updated_at": func.now(),
                },
                where=stmt.excluded.score_date >= EpssCurrentScore.score_date,
            )
        )


def _upsert_summary(session: Session, records: list[dict]) -> None:
    for score_date in {record["score_date"] for record in records}:
        (
            record_count,
            average_score,
            maximum_score,
            low_risk_count,
            medium_risk_count,
            high_risk_count,
        ) = session.execute(
            select(
                func.count(),
                func.avg(EpssScore.epss_score),
                func.max(EpssScore.epss_score),
                func.count().filter(EpssScore.epss_score < 0.1),
                func.count().filter(EpssScore.epss_score >= 0.1, EpssScore.epss_score < 0.5),
                func.count().filter(EpssScore.epss_score >= 0.5),
            ).where(EpssScore.score_date == score_date)
        ).one()
        values = {
            "score_date": score_date,
            "record_count": record_count,
            "average_score": average_score,
            "maximum_score": maximum_score,
            "low_risk_count": low_risk_count,
            "medium_risk_count": medium_risk_count,
            "high_risk_count": high_risk_count,
        }
        stmt = insert(EpssDailySummary).values(values)
        session.execute(
            stmt.on_conflict_do_update(
                index_elements=[EpssDailySummary.score_date],
                set_={key: getattr(stmt.excluded, key) for key in values if key != "score_date"}
                | {"updated_at": func.now()},
            )
        )


def prune_history(session: Session, *, latest_date: date, retention_days: int) -> int:
    if retention_days < 1:
        raise ValueError("retention_days must be positive")
    cutoff = latest_date - timedelta(days=retention_days - 1)
    result = session.execute(delete(EpssScore).where(EpssScore.score_date < cutoff))
    return int(result.rowcount or 0)
