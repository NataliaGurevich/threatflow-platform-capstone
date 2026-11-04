"""Persistence helpers for normalized CISA KEV change events."""

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.cisa_change import CisaKevChange


def upsert_changes(session: Session, changes: list[dict], *, batch_size: int = 500) -> int:
    for offset in range(0, len(changes), batch_size):
        batch = changes[offset : offset + batch_size]
        statement = insert(CisaKevChange).values(batch)
        session.execute(
            statement.on_conflict_do_update(
                constraint="uq_cisa_kev_changes_commit_cve",
                set_={
                    "revision_type": statement.excluded.revision_type,
                    "committed_at": statement.excluded.committed_at,
                    "change_type": statement.excluded.change_type,
                    "changed_fields": statement.excluded.changed_fields,
                    "previous_values": statement.excluded.previous_values,
                    "current_values": statement.excluded.current_values,
                },
            )
        )
    return len(changes)
