"""Verify local Raw artifacts and attach idempotent Amazon S3 Bronze locations."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import create_engine, exists, select
from sqlalchemy.orm import Session, aliased

from threatflow.config import Settings
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import (
    RawArtifactRef,
    RawArtifactStore,
    calculate_sha256,
    supported_raw_sources,
)
from threatflow.repository.raw_artifact_repository import record_artifact_location
from threatflow.s3_raw_storage import build_s3_object_key

LOGGER = logging.getLogger(__name__)

_CISA_BRONZE_REQUEST_MODES = ("snapshot", "git_history")


@dataclass(frozen=True)
class ReconciliationCandidate:
    artifact_id: int
    source: str
    sha256: str
    extension: str
    size_bytes: int
    acquired_at: datetime
    local_uri: str


@dataclass(frozen=True)
class ReconciliationIssue:
    artifact_id: int
    source: str
    sha256: str
    message: str


@dataclass(frozen=True)
class ReconciliationResult:
    source: str
    dry_run: bool
    scanned: int
    verified: int
    planned: int
    uploaded: int
    reused: int
    total_bytes: int
    target_uris: tuple[str, ...]
    issues: tuple[ReconciliationIssue, ...]


class LocationRecorder(Protocol):
    def __call__(
        self,
        candidate: ReconciliationCandidate,
        location: RawArtifactRef,
        verified_at: datetime,
    ) -> None: ...


class LocalArtifactIntegrityError(OSError):
    """Raised when a local copy no longer matches its manifest identity."""


def list_reconciliation_candidates(
    session: Session,
    source: str,
    *,
    limit: int | None = None,
) -> list[ReconciliationCandidate]:
    """Return local artifacts that do not yet have a verified S3 location."""
    if source not in supported_raw_sources():
        raise ValueError(f"unsupported source: {source}")
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    local_location = aliased(RawArtifactLocation)
    has_s3_location = exists(
        select(RawArtifactLocation.id).where(
            RawArtifactLocation.artifact_id == RawArtifact.id,
            RawArtifactLocation.backend == "s3",
        )
    )
    statement = (
        select(
            RawArtifact.id,
            RawArtifact.source,
            RawArtifact.sha256,
            RawArtifact.extension,
            RawArtifact.size_bytes,
            RawArtifact.first_acquired_at,
            local_location.uri,
        )
        .join(
            local_location,
            (local_location.artifact_id == RawArtifact.id)
            & (local_location.backend == "local"),
        )
        .where(RawArtifact.source == source, ~has_s3_location)
        .order_by(RawArtifact.id)
    )
    if source == "cisa_kev":
        statement = statement.where(
            RawArtifact.request_mode.in_(_CISA_BRONZE_REQUEST_MODES)
        )
    if limit is not None:
        statement = statement.limit(limit)

    return [
        ReconciliationCandidate(
            artifact_id=row.id,
            source=row.source,
            sha256=row.sha256,
            extension=row.extension,
            size_bytes=row.size_bytes,
            acquired_at=row.first_acquired_at,
            local_uri=row.uri,
        )
        for row in session.execute(statement)
    ]


def reconcile_candidates(
    candidates: Iterable[ReconciliationCandidate],
    *,
    source: str,
    bucket: str,
    prefix: str,
    local_store: RawArtifactStore,
    dry_run: bool,
    target_store: RawArtifactStore | None = None,
    record_location: LocationRecorder | None = None,
) -> ReconciliationResult:
    """Validate candidates, optionally upload them, and persist each verified S3 copy."""
    if not bucket.strip():
        raise ValueError("bucket must not be empty")
    if source not in supported_raw_sources():
        raise ValueError(f"unsupported source: {source}")
    if not prefix.strip("/"):
        raise ValueError("prefix must contain at least one non-slash character")
    if local_store.backend != "local":
        raise ValueError("local_store must use the local backend")

    candidate_list = list(candidates)
    if not dry_run and candidate_list and (target_store is None or record_location is None):
        raise ValueError("apply mode requires target_store and record_location")
    if target_store is not None and target_store.backend != "s3":
        raise ValueError("target_store must use the s3 backend")
    verified = planned = uploaded = reused = total_bytes = 0
    target_uris: list[str] = []
    issues: list[ReconciliationIssue] = []

    for candidate in candidate_list:
        if candidate.source != source:
            raise ValueError("all reconciliation candidates must match the requested source")
        object_key = build_s3_object_key(
            prefix,
            candidate.source,
            candidate.sha256,
            candidate.extension,
        )
        target_uri = f"s3://{bucket}/{object_key}"
        try:
            content = _read_and_validate(candidate, local_store)
        except (OSError, TypeError, ValueError) as exc:
            if not dry_run:
                raise
            issues.append(
                ReconciliationIssue(
                    artifact_id=candidate.artifact_id,
                    source=candidate.source,
                    sha256=candidate.sha256,
                    message=str(exc),
                )
            )
            continue

        verified += 1
        total_bytes += len(content)
        target_uris.append(target_uri)
        if dry_run:
            planned += 1
            continue

        assert target_store is not None
        assert record_location is not None
        location = target_store.store(
            candidate.source,
            content,
            candidate.acquired_at,
            candidate.extension,
        )
        _validate_target_location(
            candidate,
            location,
            expected_uri=target_uri,
            expected_bucket=bucket,
            expected_key=object_key,
        )
        record_location(candidate, location, datetime.now(UTC))
        if location.created:
            uploaded += 1
        else:
            reused += 1

    return ReconciliationResult(
        source=source,
        dry_run=dry_run,
        scanned=len(candidate_list),
        verified=verified,
        planned=planned,
        uploaded=uploaded,
        reused=reused,
        total_bytes=total_bytes,
        target_uris=tuple(target_uris),
        issues=tuple(issues),
    )


def reconcile_raw_storage(
    settings: Settings,
    *,
    source: str,
    dry_run: bool,
    bucket: str | None = None,
    prefix: str | None = None,
    limit: int | None = None,
    local_store: RawArtifactStore | None = None,
    target_store: RawArtifactStore | None = None,
) -> ReconciliationResult:
    """Run reconciliation against PostgreSQL, committing each S3 location independently."""
    resolved_bucket = settings.s3_bronze_bucket if bucket is None else bucket
    resolved_prefix = settings.s3_bronze_prefix if prefix is None else prefix
    if not resolved_bucket:
        raise ValueError("S3 Bronze bucket is required for reconciliation")

    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            candidates = list_reconciliation_candidates(session, source, limit=limit)

        effective_local_store = local_store or LocalRawArtifactStore(settings.raw_data_dir)
        effective_target_store = target_store
        if not dry_run and candidates and effective_target_store is None:
            from threatflow.s3_raw_storage import S3RawArtifactStore

            effective_target_store = S3RawArtifactStore(
                bucket=resolved_bucket,
                prefix=resolved_prefix,
                region_name=settings.aws_region,
                connect_timeout=settings.http_connect_timeout,
                read_timeout=settings.http_read_timeout,
                max_attempts=settings.http_retries + 1,
            )

        def persist_location(
            candidate: ReconciliationCandidate,
            location: RawArtifactRef,
            verified_at: datetime,
        ) -> None:
            with Session(engine) as write_session, write_session.begin():
                record_artifact_location(
                    write_session,
                    candidate.artifact_id,
                    location,
                    verified_at,
                )

        return reconcile_candidates(
            candidates,
            source=source,
            bucket=resolved_bucket,
            prefix=resolved_prefix,
            local_store=effective_local_store,
            dry_run=dry_run,
            target_store=effective_target_store,
            record_location=None if dry_run else persist_location,
        )
    finally:
        engine.dispose()


def _read_and_validate(
    candidate: ReconciliationCandidate,
    local_store: RawArtifactStore,
) -> bytes:
    content = local_store.read(candidate.local_uri)
    if len(content) != candidate.size_bytes:
        raise LocalArtifactIntegrityError(
            f"local size mismatch: expected {candidate.size_bytes}, got {len(content)}"
        )
    digest = calculate_sha256(content)
    if digest != candidate.sha256:
        raise LocalArtifactIntegrityError(
            f"local SHA-256 mismatch: expected {candidate.sha256}, got {digest}"
        )
    return content


def _validate_target_location(
    candidate: ReconciliationCandidate,
    location: RawArtifactRef,
    *,
    expected_uri: str,
    expected_bucket: str,
    expected_key: str,
) -> None:
    expected_identity = (
        candidate.source,
        candidate.sha256,
        candidate.extension,
        candidate.size_bytes,
    )
    actual_identity = (
        location.source,
        location.sha256,
        location.extension,
        location.size_bytes,
    )
    if location.backend != "s3" or location.uri != expected_uri:
        raise ValueError("S3 adapter returned an unexpected target locator")
    if location.bucket != expected_bucket or location.object_key != expected_key:
        raise ValueError("S3 adapter returned inconsistent bucket or object key metadata")
    if actual_identity != expected_identity:
        raise ValueError("S3 adapter returned an artifact with a different identity")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify local Raw artifacts and reconcile missing Amazon S3 locations."
    )
    parser.add_argument("--source", required=True, choices=supported_raw_sources())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Validate and plan without AWS calls")
    mode.add_argument("--apply", action="store_true", help="Upload and record S3 locations")
    parser.add_argument("--bucket", help="Override THREATFLOW_S3_BRONZE_BUCKET")
    parser.add_argument("--prefix", help="Override THREATFLOW_S3_BRONZE_PREFIX")
    parser.add_argument("--limit", type=_positive_int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = reconcile_raw_storage(
            Settings(),
            source=args.source,
            dry_run=args.dry_run,
            bucket=args.bucket,
            prefix=args.prefix,
            limit=args.limit,
        )
    except Exception as exc:
        LOGGER.error("Raw storage reconciliation failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 2 if result.issues else 0
