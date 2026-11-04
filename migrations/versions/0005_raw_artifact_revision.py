"""Record upstream revisions for historical raw artifacts."""

import sqlalchemy as sa
from alembic import op

revision = "0005_raw_artifact_revision"
down_revision = "0004_raw_artifact_manifest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("raw_artifacts", sa.Column("source_revision", sa.String(64)))
    op.create_index("ix_raw_artifacts_source_revision", "raw_artifacts", ["source_revision"])


def downgrade() -> None:
    op.drop_index("ix_raw_artifacts_source_revision", table_name="raw_artifacts")
    op.drop_column("raw_artifacts", "source_revision")
