"""Searchable manifest for immutable raw source artifacts."""

from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from threatflow.models.base import Base


class RawArtifact(Base):
    __tablename__ = "raw_artifacts"
    __table_args__ = (
        UniqueConstraint("source", "sha256", name="uq_raw_artifacts_source_sha256"),
        Index(
            "ix_raw_artifacts_request",
            "source",
            "request_mode",
            "requested_start",
            "requested_end",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    extension: Mapped[str] = mapped_column(String(16), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    first_acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    seen_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    request_mode: Mapped[str | None] = mapped_column(String(32))
    requested_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    page_start_index: Mapped[int | None] = mapped_column(Integer)
    record_count: Mapped[int | None] = mapped_column(Integer)
    ingestion_run_id: Mapped[str | None] = mapped_column(String(250))
    source_revision: Mapped[str | None] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
