"""Add compact EPSS current state, summaries, and history lookup index."""

import sqlalchemy as sa
from alembic import op

revision = "0003_epss_storage_policy"
down_revision = "0002_ingestion_checkpoint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_epss_scores_score_date", "epss_scores", ["score_date"])
    op.create_table(
        "epss_current",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("score_date", sa.Date(), nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("ix_epss_current_score_date", "epss_current", ["score_date"])
    op.create_table(
        "epss_daily_summaries",
        sa.Column("score_date", sa.Date(), primary_key=True),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("average_score", sa.Float(), nullable=False),
        sa.Column("maximum_score", sa.Float(), nullable=False),
        sa.Column("low_risk_count", sa.Integer(), nullable=False),
        sa.Column("medium_risk_count", sa.Integer(), nullable=False),
        sa.Column("high_risk_count", sa.Integer(), nullable=False),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.execute(
        """
        INSERT INTO epss_current
            (cve_id, score_date, epss_score, percentile, created_at, updated_at)
        SELECT DISTINCT ON (cve_id)
            cve_id, score_date, epss_score, percentile, created_at, updated_at
        FROM epss_scores
        ORDER BY cve_id, score_date DESC
        """
    )
    op.execute(
        """
        INSERT INTO epss_daily_summaries
            (score_date, record_count, average_score, maximum_score,
             low_risk_count, medium_risk_count, high_risk_count)
        SELECT score_date, count(*), avg(epss_score), max(epss_score),
               count(*) FILTER (WHERE epss_score < 0.1),
               count(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5),
               count(*) FILTER (WHERE epss_score >= 0.5)
        FROM epss_scores
        GROUP BY score_date
        """
    )


def downgrade() -> None:
    op.drop_table("epss_daily_summaries")
    op.drop_index("ix_epss_current_score_date", table_name="epss_current")
    op.drop_table("epss_current")
    op.drop_index("ix_epss_scores_score_date", table_name="epss_scores")
