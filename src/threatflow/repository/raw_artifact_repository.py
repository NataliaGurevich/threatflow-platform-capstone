"""Persistence for the raw artifact manifest."""

from collections.abc import Iterable
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef


def record_artifact(
    session: Session,
    artifact: RawArtifactRef,
    acquired_at: datetime,
    *,
    request_mode: str | None = None,
    requested_start: datetime | None = None,
    requested_end: datetime | None = None,
    page_start_index: int | None = None,
    record_count: int | None = None,
    ingestion_run_id: str | None = None,
    source_revision: str | None = None,
    additional_locations: Iterable[RawArtifactRef] = (),
) -> None:
    statement = insert(RawArtifact).values(
        source=artifact.source,
        sha256=artifact.sha256,
        storage_path=artifact.uri,
        extension=artifact.extension,
        size_bytes=artifact.size_bytes,
        first_acquired_at=acquired_at,
        last_seen_at=acquired_at,
        request_mode=request_mode,
        requested_start=requested_start,
        requested_end=requested_end,
        page_start_index=page_start_index,
        record_count=record_count,
        ingestion_run_id=ingestion_run_id,
        source_revision=source_revision,
    )
    excluded = statement.excluded
    statement = statement.on_conflict_do_update(
        constraint="uq_raw_artifacts_source_sha256",
        set_={
            "last_seen_at": acquired_at,
            "seen_count": RawArtifact.seen_count + 1,
            "request_mode": func.coalesce(RawArtifact.request_mode, excluded.request_mode),
            "requested_start": func.coalesce(RawArtifact.requested_start, excluded.requested_start),
            "requested_end": func.coalesce(RawArtifact.requested_end, excluded.requested_end),
            "page_start_index": excluded.page_start_index,
            "record_count": excluded.record_count,
            "ingestion_run_id": excluded.ingestion_run_id,
            "source_revision": func.coalesce(RawArtifact.source_revision, excluded.source_revision),
            "updated_at": acquired_at,
        },
    ).returning(RawArtifact.id)
    artifact_id = session.execute(statement).scalar_one()

    _upsert_artifact_location(session, artifact_id, artifact, acquired_at)
    for location in additional_locations:
        _validate_location_identity(artifact, location)
        _upsert_artifact_location(session, artifact_id, location, acquired_at)


def record_artifact_location(
    session: Session,
    artifact_id: int,
    location: RawArtifactRef,
    verified_at: datetime,
) -> None:
    """Attach or refresh a verified physical copy without recording a source observation."""
    manifest = session.get(RawArtifact, artifact_id)
    if manifest is None:
        raise ValueError(f"raw artifact does not exist: {artifact_id}")
    _validate_location_identity(manifest, location)
    _upsert_artifact_location(session, artifact_id, location, verified_at)


def _validate_location_identity(
    manifest: RawArtifact | RawArtifactRef,
    location: RawArtifactRef,
) -> None:
    expected = (manifest.source, manifest.sha256, manifest.extension, manifest.size_bytes)
    actual = (location.source, location.sha256, location.extension, location.size_bytes)
    if actual != expected:
        raise ValueError("physical location identity does not match the raw artifact manifest")


def _upsert_artifact_location(
    session: Session,
    artifact_id: int,
    location: RawArtifactRef,
    verified_at: datetime,
) -> None:
    """Upsert one backend locator after its bytes and metadata have been verified."""

    location_statement = insert(RawArtifactLocation).values(
        artifact_id=artifact_id,
        backend=location.backend,
        uri=location.uri,
        storage_bucket=location.bucket,
        storage_key=location.object_key,
        storage_version_id=location.version_id,
        first_recorded_at=verified_at,
        last_verified_at=verified_at,
    )
    location_excluded = location_statement.excluded
    location_statement = location_statement.on_conflict_do_update(
        constraint="uq_raw_artifact_locations_artifact_backend",
        set_={
            "uri": location_excluded.uri,
            "storage_bucket": location_excluded.storage_bucket,
            "storage_key": location_excluded.storage_key,
            "storage_version_id": location_excluded.storage_version_id,
            "last_verified_at": verified_at,
            "updated_at": verified_at,
        },
    )
    session.execute(location_statement)


def artifact_location_uri(artifact: RawArtifact, backend: str) -> str:
    """Return the verified locator for a backend or fail instead of using another backend."""
    for location in artifact.locations:
        if location.backend == backend:
            return location.uri
    raise FileNotFoundError(
        f"raw artifact {artifact.source}/{artifact.sha256} has no {backend!r} location"
    )
