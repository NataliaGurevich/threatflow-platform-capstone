"""Persist successful NVD modification coverage outside Airflow metadata."""

import sqlalchemy as sa
from alembic import op

revision = "0002_ingestion_checkpoint"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ingestion_checkpoints",
        sa.Column("source", sa.String(32), primary_key=True),
        sa.Column("covered_until", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade():
    op.drop_table("ingestion_checkpoints")
