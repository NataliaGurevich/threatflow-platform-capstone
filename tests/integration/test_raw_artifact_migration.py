"""Alembic runtime coverage for Raw artifact location migration and backfill."""

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, make_url, text
from testcontainers.core.docker_client import DockerClient

pytest.importorskip("testcontainers.postgres")
from testcontainers.postgres import PostgresContainer


def test_migration_backfills_existing_manifest_path_as_local_location(monkeypatch):
    try:
        DockerClient().client.ping()
    except Exception as exc:
        pytest.skip(f"Docker daemon unavailable for isolated PostgreSQL test: {exc}")

    with PostgresContainer("postgres:17-alpine") as postgres:
        database_url = postgres.get_connection_url().replace("psycopg2", "psycopg")
        parsed = make_url(database_url)
        monkeypatch.setenv("THREATFLOW_POSTGRES_HOST", parsed.host or "localhost")
        monkeypatch.setenv("THREATFLOW_POSTGRES_PORT", str(parsed.port or 5432))
        monkeypatch.setenv("THREATFLOW_POSTGRES_DB", parsed.database or "test")
        monkeypatch.setenv("THREATFLOW_POSTGRES_USER", parsed.username or "test")
        monkeypatch.setenv("THREATFLOW_POSTGRES_PASSWORD", parsed.password or "test")

        config = Config("alembic.ini")
        command.upgrade(config, "0007_cisa_daily_changes")
        engine = create_engine(database_url)
        with engine.begin() as connection:
            artifact_id = connection.scalar(
                text(
                    """
                    INSERT INTO raw_artifacts (
                        source,
                        sha256,
                        storage_path,
                        extension,
                        size_bytes,
                        first_acquired_at,
                        last_seen_at
                    )
                    VALUES (
                        'epss',
                        :sha256,
                        :storage_path,
                        'csv.gz',
                        42,
                        '2026-11-10T10:00:00+00:00',
                        '2026-11-11T10:00:00+00:00'
                    )
                    RETURNING id
                    """
                ),
                {
                    "sha256": "a" * 64,
                    "storage_path": "data/raw/epss/year=2026/month=11/artifact.csv.gz",
                },
            )

        command.upgrade(config, "head")
        with engine.connect() as connection:
            location = (
                connection.execute(
                    text(
                    """
                    SELECT artifact_id, backend, uri, storage_bucket, storage_key
                    FROM raw_artifact_locations
                    """
                    )
                )
                .mappings()
                .one()
            )
            assert location == {
                "artifact_id": artifact_id,
                "backend": "local",
                "uri": "data/raw/epss/year=2026/month=11/artifact.csv.gz",
                "storage_bucket": None,
                "storage_key": None,
            }

        command.downgrade(config, "0007_cisa_daily_changes")
        assert "raw_artifact_locations" not in inspect(engine).get_table_names()
        engine.dispose()
