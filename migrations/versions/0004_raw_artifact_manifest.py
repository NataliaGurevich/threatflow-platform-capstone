"""Add searchable provenance manifest for immutable raw artifacts."""

import sqlalchemy as sa
from alembic import op

revision = "0004_raw_artifact_manifest"
down_revision = "0003_epss_storage_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "raw_artifacts",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("storage_path", sa.Text(), nullable=False),
        sa.Column("extension", sa.String(16), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("first_acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("seen_count", sa.Integer(), server_default="1", nullable=False),
        sa.Column("request_mode", sa.String(32)),
        sa.Column("requested_start", sa.DateTime(timezone=True)),
        sa.Column("requested_end", sa.DateTime(timezone=True)),
        sa.Column("page_start_index", sa.Integer()),
        sa.Column("record_count", sa.Integer()),
        sa.Column("ingestion_run_id", sa.String(250)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("source", "sha256", name="uq_raw_artifacts_source_sha256"),
    )
    op.create_index(
        "ix_raw_artifacts_request",
        "raw_artifacts",
        ["source", "request_mode", "requested_start", "requested_end"],
    )


def downgrade() -> None:
    op.drop_index("ix_raw_artifacts_request", table_name="raw_artifacts")
    op.drop_table("raw_artifacts")
