"""Bulk PostgreSQL upsert for CISA KEV records."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.cisa import CisaKevVulnerability


def upsert_records(
    session: Session, records: list[dict], *, batch_size: int = 500
) -> tuple[int, int]:
    inserted = updated = 0
    columns = [
        "cve_id",
        "vendor_project",
        "product",
        "vulnerability_name",
        "date_added",
        "short_description",
        "required_action",
        "due_date",
        "known_ransomware_campaign_use",
        "notes",
    ]
    for start in range(0, len(records), batch_size):
        batch = records[start : start + batch_size]
        existing = set(
            session.scalars(
                select(CisaKevVulnerability.cve_id).where(
                    CisaKevVulnerability.cve_id.in_([r["cve_id"] for r in batch])
                )
            )
        )
        statement = insert(CisaKevVulnerability).values(batch)
        statement = statement.on_conflict_do_update(
            index_elements=[CisaKevVulnerability.cve_id],
            set_={key: getattr(statement.excluded, key) for key in columns if key != "cve_id"}
            | {"updated_at": func.now()},
        )
        session.execute(statement)
        updated += sum(r["cve_id"] in existing for r in batch)
        inserted += len(batch) - sum(r["cve_id"] in existing for r in batch)
    return inserted, updated
