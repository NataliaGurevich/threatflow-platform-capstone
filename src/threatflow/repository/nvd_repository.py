"""Bulk PostgreSQL upsert for current NVD CVE records."""

from sqlalchemy import func, or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.nvd import NvdCve


def upsert_records(
    session: Session, records: list[dict], *, batch_size: int = 500
) -> tuple[int, int]:
    if batch_size < 1:
        raise ValueError("batch_size must be positive")
    inserted = updated = 0
    columns = [
        "description",
        "published",
        "last_modified",
        "cvss_version",
        "cvss_score",
        "cvss_severity",
        "cvss_vector",
        "cwe_ids",
        "references",
    ]
    for offset in range(0, len(records), batch_size):
        batch = records[offset : offset + batch_size]
        ids = [record["cve_id"] for record in batch]
        existing = set(session.scalars(select(NvdCve.cve_id).where(NvdCve.cve_id.in_(ids))))
        insert_stmt = insert(NvdCve).values(batch)
        statement = insert_stmt.on_conflict_do_update(
            index_elements=[NvdCve.cve_id],
            set_={key: getattr(insert_stmt.excluded, key) for key in columns}
            | {"updated_at": func.now()},
            where=or_(
                NvdCve.last_modified.is_(None),
                insert_stmt.excluded.last_modified >= NvdCve.last_modified,
            ),
        )
        affected = set(session.scalars(statement.returning(NvdCve.cve_id)))
        count = len(affected & existing)
        updated += count
        inserted += len(affected - existing)
    return inserted, updated
