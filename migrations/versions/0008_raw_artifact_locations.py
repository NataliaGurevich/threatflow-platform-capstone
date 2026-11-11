"""Track multiple physical locations for each logical raw artifact."""

import sqlalchemy as sa
from alembic import op

revision = "0008_raw_artifact_locations"
down_revision = "0007_cisa_daily_changes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "raw_artifact_locations",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column(
            "artifact_id",
            sa.BigInteger(),
            sa.ForeignKey("raw_artifacts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("backend", sa.String(16), nullable=False),
        sa.Column("uri", sa.Text(), nullable=False),
        sa.Column("storage_bucket", sa.String(255)),
        sa.Column("storage_key", sa.Text()),
        sa.Column("storage_version_id", sa.Text()),
        sa.Column("first_recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint(
            "artifact_id",
            "backend",
            name="uq_raw_artifact_locations_artifact_backend",
        ),
        sa.CheckConstraint(
            "backend IN ('local', 's3')",
            name="ck_raw_artifact_locations_backend",
        ),
        sa.CheckConstraint(
            "(backend = 'local' AND storage_bucket IS NULL AND storage_key IS NULL "
            "AND storage_version_id IS NULL) OR "
            "(backend = 's3' AND storage_bucket IS NOT NULL AND storage_key IS NOT NULL)",
            name="ck_raw_artifact_locations_locator_fields",
        ),
    )
    op.create_index(
        "ix_raw_artifact_locations_artifact_id",
        "raw_artifact_locations",
        ["artifact_id"],
    )
    op.execute(
        sa.text(
            """
            INSERT INTO raw_artifact_locations (
                artifact_id,
                backend,
                uri,
                first_recorded_at,
                last_verified_at
            )
            SELECT
                id,
                'local',
                storage_path,
                first_acquired_at,
                last_seen_at
            FROM raw_artifacts
            """
        )
    )


def downgrade() -> None:
    op.drop_index(
        "ix_raw_artifact_locations_artifact_id",
        table_name="raw_artifact_locations",
    )
    op.drop_table("raw_artifact_locations")
