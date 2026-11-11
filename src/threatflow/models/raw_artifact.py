"""Searchable manifest for immutable raw source artifacts."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

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
    locations: Mapped[list[RawArtifactLocation]] = relationship(
        back_populates="artifact",
        cascade="all, delete-orphan",
    )


class RawArtifactLocation(Base):
    """One verified physical copy of a logical raw artifact."""

    __tablename__ = "raw_artifact_locations"
    __table_args__ = (
        UniqueConstraint(
            "artifact_id",
            "backend",
            name="uq_raw_artifact_locations_artifact_backend",
        ),
        CheckConstraint(
            "backend IN ('local', 's3')",
            name="ck_raw_artifact_locations_backend",
        ),
        CheckConstraint(
            "(backend = 'local' AND storage_bucket IS NULL AND storage_key IS NULL "
            "AND storage_version_id IS NULL) OR "
            "(backend = 's3' AND storage_bucket IS NOT NULL AND storage_key IS NOT NULL)",
            name="ck_raw_artifact_locations_locator_fields",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    artifact_id: Mapped[int] = mapped_column(
        ForeignKey("raw_artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    backend: Mapped[str] = mapped_column(String(16), nullable=False)
    uri: Mapped[str] = mapped_column(Text, nullable=False)
    storage_bucket: Mapped[str | None] = mapped_column(String(255))
    storage_key: Mapped[str | None] = mapped_column(Text)
    storage_version_id: Mapped[str | None] = mapped_column(Text)
    first_recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_verified_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    artifact: Mapped[RawArtifact] = relationship(back_populates="locations")
