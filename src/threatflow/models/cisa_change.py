"""Historical changes derived from official CISA KEV Git snapshots."""

from datetime import datetime

from sqlalchemy import BigInteger, CheckConstraint, DateTime, Index, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from threatflow.models.base import Base


class CisaKevChange(Base):
    __tablename__ = "cisa_kev_changes"
    __table_args__ = (
        CheckConstraint(
            "change_type IN ('baseline', 'added', 'modified', 'removed')",
            name="ck_cisa_kev_changes_type",
        ),
        UniqueConstraint("commit_sha", "cve_id", name="uq_cisa_kev_changes_commit_cve"),
        Index("ix_cisa_kev_changes_cve_time", "cve_id", "committed_at"),
        Index("ix_cisa_kev_changes_time", "committed_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    revision_type: Mapped[str] = mapped_column(String(16), nullable=False)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    change_type: Mapped[str] = mapped_column(String(16), nullable=False)
    changed_fields: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    previous_values: Mapped[dict | None] = mapped_column(JSONB)
    current_values: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
