"""Daily EPSS score model."""

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, Index, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from threatflow.models.base import Base


class EpssScore(Base):
    __tablename__ = "epss_scores"
    __table_args__ = (Index("ix_epss_scores_score_date", "score_date"),)

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score_date: Mapped[date] = mapped_column(Date, primary_key=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class EpssCurrentScore(Base):
    __tablename__ = "epss_current"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    score_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False)
    percentile: Mapped[float] = mapped_column(Float, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class EpssDailySummary(Base):
    __tablename__ = "epss_daily_summaries"

    score_date: Mapped[date] = mapped_column(Date, primary_key=True)
    record_count: Mapped[int] = mapped_column(Integer, nullable=False)
    average_score: Mapped[float] = mapped_column(Float, nullable=False)
    maximum_score: Mapped[float] = mapped_column(Float, nullable=False)
    low_risk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    medium_risk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    high_risk_count: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
