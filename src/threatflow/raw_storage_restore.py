"""Restore one verified Amazon S3 Bronze artifact to local Raw storage."""

from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from threatflow.config import Settings
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef, RawArtifactStore, calculate_sha256
from threatflow.repository.raw_artifact_repository import record_artifact_location
from threatflow.s3_raw_storage import S3RawArtifactStore

LOGGER = logging.getLogger(__name__)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RawArtifactRestoreResult:
    source: str
    sha256: str
    size_bytes: int
    s3_uri: str
    local_uri: str
    local_created: bool
    manifest_updated: bool


def restore_artifact(
    artifact: RawArtifact,
    s3_location: RawArtifactLocation,
    *,
    s3_store: RawArtifactStore,
    local_store: RawArtifactStore,
) -> RawArtifactRef:
    """Download, verify, and atomically publish one local copy."""
    if s3_store.backend != "s3":
        raise ValueError("s3_store must use the s3 backend")
    if local_store.backend != "local":
        raise ValueError("local_store must use the local backend")
    if s3_location.backend != "s3":
        raise ValueError("restore requires an S3 artifact location")

    s3_ref = RawArtifactRef(
        source=artifact.source,
        sha256=artifact.sha256,
        uri=s3_location.uri,
        extension=artifact.extension,
        content_type="application/octet-stream",
        size_bytes=artifact.size_bytes,
        created=False,
        backend="s3",
        bucket=s3_location.storage_bucket,
        object_key=s3_location.storage_key,
        version_id=s3_location.storage_version_id,
    )
    content = s3_store.read(s3_ref)
    if len(content) != artifact.size_bytes:
        raise OSError(
            f"restored size mismatch: expected {artifact.size_bytes}, got {len(content)}"
        )
    digest = calculate_sha256(content)
    if digest != artifact.sha256:
        raise OSError(
            f"restored SHA-256 mismatch: expected {artifact.sha256}, got {digest}"
        )

    local_ref = local_store.store(
        artifact.source,
        content,
        artifact.first_acquired_at,
        artifact.extension,
    )
    expected = (artifact.source, artifact.sha256, artifact.extension, artifact.size_bytes)
    actual = (
        local_ref.source,
        local_ref.sha256,
        local_ref.extension,
        local_ref.size_bytes,
    )
    if local_ref.backend != "local" or actual != expected:
        raise ValueError("restored local artifact identity does not match the manifest")
    return local_ref


def restore_raw_artifact(
    settings: Settings,
    *,
    source: str,
    sha256: str,
    s3_store: RawArtifactStore | None = None,
    local_store: RawArtifactStore | None = None,
    update_manifest: bool = True,
) -> RawArtifactRestoreResult:
    """Restore one manifest-selected S3 object without creating a source observation."""
    if not _SHA256.fullmatch(sha256):
        raise ValueError("sha256 must contain exactly 64 lowercase hexadecimal characters")
    if not settings.s3_bronze_bucket:
        raise ValueError("S3 Bronze bucket is required for restore")

    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            artifact = session.scalar(
                select(RawArtifact)
                .options(selectinload(RawArtifact.locations))
                .where(RawArtifact.source == source, RawArtifact.sha256 == sha256)
            )
            if artifact is None:
                raise FileNotFoundError(f"raw artifact is not in the manifest: {source}/{sha256}")
            s3_location = next(
                (location for location in artifact.locations if location.backend == "s3"),
                None,
            )
            if s3_location is None:
                raise FileNotFoundError(
                    f"raw artifact has no verified S3 location: {source}/{sha256}"
                )
            artifact_id = artifact.id

            effective_s3_store = s3_store or S3RawArtifactStore(
                bucket=settings.s3_bronze_bucket,
                prefix=settings.s3_bronze_prefix,
                region_name=settings.aws_region,
                connect_timeout=settings.http_connect_timeout,
                read_timeout=settings.http_read_timeout,
                max_attempts=settings.http_retries + 1,
            )
            effective_local_store = local_store or LocalRawArtifactStore(settings.raw_data_dir)
            restored = restore_artifact(
                artifact,
                s3_location,
                s3_store=effective_s3_store,
                local_store=effective_local_store,
            )

        if update_manifest:
            with Session(engine) as write_session, write_session.begin():
                record_artifact_location(
                    write_session,
                    artifact_id,
                    restored,
                    datetime.now(UTC),
                )

        return RawArtifactRestoreResult(
            source=artifact.source,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            s3_uri=s3_location.uri,
            local_uri=restored.uri,
            local_created=restored.created,
            manifest_updated=update_manifest,
        )
    finally:
        engine.dispose()


def _sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must contain exactly 64 lowercase hexadecimal characters"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Restore one manifest-selected S3 Bronze object to local Raw storage and "
            "refresh its verified local location."
        )
    )
    parser.add_argument("--source", required=True, choices=("cisa_kev", "nvd", "epss"))
    parser.add_argument("--sha256", required=True, type=_sha256)
    parser.add_argument(
        "--target-dir",
        type=Path,
        help=(
            "Restore into a separate Raw root without changing the manifest; "
            "intended for a non-invasive recovery drill"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = restore_raw_artifact(
            Settings(),
            source=args.source,
            sha256=args.sha256,
            local_store=(
                LocalRawArtifactStore(args.target_dir) if args.target_dir is not None else None
            ),
            update_manifest=args.target_dir is None,
        )
    except (
        BotoCoreError,
        ClientError,
        FileNotFoundError,
        OSError,
        SQLAlchemyError,
        ValueError,
    ) as exc:
        LOGGER.error("Raw artifact restore failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
