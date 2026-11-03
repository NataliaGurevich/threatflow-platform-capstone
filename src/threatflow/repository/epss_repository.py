"""PostgreSQL bulk upsert for daily EPSS scores."""

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.epss import EpssScore


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
    return inserted, updated
