"""Create exactly the initial three application tables."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cisa_kev_vulnerabilities",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("vendor_project", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        sa.Column("vulnerability_name", sa.Text(), nullable=False),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column("short_description", sa.Text(), nullable=False),
        sa.Column("required_action", sa.Text(), nullable=False),
        sa.Column("due_date", sa.Date(), nullable=False),
        sa.Column("known_ransomware_campaign_use", sa.String(32), nullable=False),
        sa.Column("notes", sa.Text()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "nvd_cves",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("description", sa.Text()),
        sa.Column("published", sa.DateTime(timezone=True)),
        sa.Column("last_modified", sa.DateTime(timezone=True)),
        sa.Column("cvss_version", sa.String(16)),
        sa.Column("cvss_score", sa.Float()),
        sa.Column("cvss_severity", sa.String(16)),
        sa.Column("cvss_vector", sa.Text()),
        sa.Column("cwe_ids", postgresql.JSONB()),
        sa.Column("references", postgresql.JSONB()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "epss_scores",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("score_date", sa.Date(), primary_key=True),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_table("epss_scores")
    op.drop_table("nvd_cves")
    op.drop_table("cisa_kev_vulnerabilities")
