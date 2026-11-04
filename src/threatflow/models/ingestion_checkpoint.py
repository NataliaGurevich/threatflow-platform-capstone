"""Durable source coverage checkpoints used by orchestration."""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from threatflow.models.base import Base


class IngestionCheckpoint(Base):
    __tablename__ = "ingestion_checkpoints"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    covered_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
