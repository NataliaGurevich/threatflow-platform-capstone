"""Support content revisions for incremental daily CISA changes."""

import sqlalchemy as sa
from alembic import op

revision = "0007_cisa_daily_changes"
down_revision = "0006_cisa_kev_changes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "cisa_kev_changes",
        "commit_sha",
        existing_type=sa.String(40),
        type_=sa.String(64),
        existing_nullable=False,
    )
    op.add_column(
        "cisa_kev_changes",
        sa.Column("revision_type", sa.String(16), server_default="git_commit", nullable=False),
    )
    op.alter_column("cisa_kev_changes", "revision_type", server_default=None)


def downgrade() -> None:
    op.drop_column("cisa_kev_changes", "revision_type")
    op.alter_column(
        "cisa_kev_changes",
        "commit_sha",
        existing_type=sa.String(64),
        type_=sa.String(40),
        existing_nullable=False,
    )
