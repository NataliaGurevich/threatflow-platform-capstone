"""Add normalized CISA KEV change history."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_cisa_kev_changes"
down_revision = "0005_raw_artifact_revision"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cisa_kev_changes",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("commit_sha", sa.String(40), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=False),
        sa.Column("change_type", sa.String(16), nullable=False),
        sa.Column("changed_fields", postgresql.JSONB(), nullable=False),
        sa.Column("previous_values", postgresql.JSONB()),
        sa.Column("current_values", postgresql.JSONB()),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "change_type IN ('baseline', 'added', 'modified', 'removed')",
            name="ck_cisa_kev_changes_type",
        ),
        sa.UniqueConstraint("commit_sha", "cve_id", name="uq_cisa_kev_changes_commit_cve"),
    )
    op.create_index("ix_cisa_kev_changes_cve_time", "cisa_kev_changes", ["cve_id", "committed_at"])
    op.create_index("ix_cisa_kev_changes_time", "cisa_kev_changes", ["committed_at"])


def downgrade() -> None:
    op.drop_index("ix_cisa_kev_changes_time", table_name="cisa_kev_changes")
    op.drop_index("ix_cisa_kev_changes_cve_time", table_name="cisa_kev_changes")
    op.drop_table("cisa_kev_changes")
