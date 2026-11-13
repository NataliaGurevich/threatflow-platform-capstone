"""Build CISA Silver snapshots from accepted entries in the local Raw manifest."""

from __future__ import annotations

import argparse
import json
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, aliased

from threatflow.config import Settings
from threatflow.ingestion.cisa_parser import parse_catalog_document
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.transformation.cisa_silver import (
    CisaSilverResult,
    SnapshotKind,
    transform_cisa_bytes,
    verify_committed_cisa_partition,
)

LOGGER = logging.getLogger(__name__)
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class CisaBootstrapCandidate:
    artifact_id: int
    sha256: str
    request_mode: SnapshotKind
    source_revision: str | None
    record_count: int
    size_bytes: int
    acquired_at: datetime
    observed_at: datetime
    local_uri: str
    lineage_uri: str
    source_version_id: str | None = None

    @property
    def snapshot_id(self) -> str:
        if self.request_mode == "git_history":
            if self.source_revision is None:
                raise ValueError(f"CISA Raw artifact {self.artifact_id} has no Git revision")
            return self.source_revision
        return self.sha256


@dataclass(frozen=True)
class CisaBootstrapSelection:
    available: int
    candidates: tuple[CisaBootstrapCandidate, ...]


@dataclass(frozen=True)
class CisaBootstrapIssue:
    artifact_id: int
    snapshot_id: str
    message: str


@dataclass(frozen=True)
class CisaBootstrapResult:
    dry_run: bool
    available: int
    selected: int
    verified: int
    planned: int
    created: int
    reused: int
    record_count: int
    issues: tuple[CisaBootstrapIssue, ...]


class RawReader(Protocol):
    def read(self, artifact: RawArtifactRef | str) -> bytes: ...


SilverTransformer = Callable[..., CisaSilverResult]
CommittedVerifier = Callable[..., CisaSilverResult | None]


class CisaBootstrapItemError(RuntimeError):
    """One item failed after prior snapshots may already have committed safely."""


def load_cisa_bootstrap_candidates(session: Session) -> list[CisaBootstrapCandidate]:
    """Load accepted CISA snapshots; diagnostic invalid history is excluded in SQL."""
    local_location = aliased(RawArtifactLocation)
    s3_location = aliased(RawArtifactLocation)
    statement = (
        select(
            RawArtifact.id,
            RawArtifact.sha256,
            RawArtifact.request_mode,
            RawArtifact.source_revision,
            RawArtifact.record_count,
            RawArtifact.size_bytes,
            RawArtifact.first_acquired_at,
            RawArtifact.requested_start,
            local_location.uri.label("local_uri"),
            s3_location.uri.label("s3_uri"),
            s3_location.storage_version_id.label("s3_version_id"),
        )
        .outerjoin(
            local_location,
            (local_location.artifact_id == RawArtifact.id)
            & (local_location.backend == "local"),
        )
        .outerjoin(
            s3_location,
            (s3_location.artifact_id == RawArtifact.id) & (s3_location.backend == "s3"),
        )
        .where(
            RawArtifact.source == "cisa_kev",
            RawArtifact.request_mode.in_(["snapshot", "git_history"]),
        )
        .order_by(RawArtifact.requested_start, RawArtifact.first_acquired_at, RawArtifact.id)
    )
    candidates: list[CisaBootstrapCandidate] = []
    for row in session.execute(statement):
        if row.record_count is None or row.record_count < 1:
            raise ValueError(f"CISA Raw artifact {row.id} has no valid record_count")
        if not row.local_uri:
            raise FileNotFoundError(f"CISA Raw artifact {row.id} has no local location")
        if row.first_acquired_at.tzinfo is None or row.first_acquired_at.utcoffset() is None:
            raise ValueError(f"CISA Raw artifact {row.id} has naive acquisition time")
        observed_at = row.requested_start or row.first_acquired_at
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError(f"CISA Raw artifact {row.id} has naive observation time")
        candidates.append(
            CisaBootstrapCandidate(
                artifact_id=row.id,
                sha256=row.sha256,
                request_mode=row.request_mode,
                source_revision=row.source_revision,
                record_count=row.record_count,
                size_bytes=row.size_bytes,
                acquired_at=row.first_acquired_at,
                observed_at=observed_at,
                local_uri=row.local_uri,
                lineage_uri=row.s3_uri or row.local_uri,
                source_version_id=row.s3_version_id,
            )
        )
    return candidates


def select_cisa_bootstrap_candidates(
    candidates: Iterable[CisaBootstrapCandidate], *, limit: int | None = None
) -> CisaBootstrapSelection:
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    ordered = sorted(candidates, key=lambda item: (item.observed_at, item.artifact_id))
    identities: dict[tuple[str, str], CisaBootstrapCandidate] = {}
    for candidate in ordered:
        if candidate.request_mode not in ("snapshot", "git_history"):
            raise ValueError(f"unsupported CISA request mode: {candidate.request_mode}")
        if candidate.request_mode == "git_history" and not _GIT_SHA.fullmatch(
            candidate.source_revision or ""
        ):
            raise ValueError(
                f"CISA Raw artifact {candidate.artifact_id} has an invalid Git revision"
            )
        identity = (candidate.request_mode, candidate.snapshot_id)
        previous = identities.get(identity)
        if previous is not None and previous.sha256 != candidate.sha256:
            raise ValueError(
                f"conflicting CISA Raw artifacts target {identity}: "
                f"{previous.sha256}, {candidate.sha256}"
            )
        identities[identity] = candidate
    unique = sorted(identities.values(), key=lambda item: (item.observed_at, item.artifact_id))
    available = len(unique)
    return CisaBootstrapSelection(available, tuple(unique[:limit] if limit else unique))


def run_cisa_silver_bootstrap(
    selection: CisaBootstrapSelection,
    *,
    local_store: RawReader,
    output_root: str | Path,
    dry_run: bool,
    transformer: SilverTransformer = transform_cisa_bytes,
    committed_verifier: CommittedVerifier = verify_committed_cisa_partition,
) -> CisaBootstrapResult:
    verified = planned = created = reused = record_count = 0
    issues: list[CisaBootstrapIssue] = []
    for index, candidate in enumerate(selection.candidates, start=1):
        LOGGER.info(
            "CISA Silver %s %d/%d: %s/%s",
            "validation" if dry_run else "bootstrap",
            index,
            len(selection.candidates),
            candidate.request_mode,
            candidate.snapshot_id,
        )
        try:
            content = _read_and_validate(candidate, local_store)
            verified += 1
            if dry_run:
                committed = committed_verifier(
                    output_root=output_root,
                    snapshot_kind=candidate.request_mode,
                    snapshot_id=candidate.snapshot_id,
                    source_sha256=candidate.sha256,
                    expected_record_count=candidate.record_count,
                )
                planned += committed is None
                reused += committed is not None
                record_count += candidate.record_count
                continue
            result = transformer(
                content,
                snapshot_kind=candidate.request_mode,
                source_revision=candidate.source_revision,
                source_sha256=candidate.sha256,
                source_uri=candidate.lineage_uri,
                source_version_id=candidate.source_version_id,
                acquired_at=candidate.acquired_at,
                snapshot_observed_at=candidate.observed_at,
                expected_record_count=candidate.record_count,
                output_root=output_root,
            )
            created += result.created
            reused += not result.created
            record_count += result.record_count
        except (OSError, TypeError, ValueError) as exc:
            if not dry_run:
                raise CisaBootstrapItemError(
                    f"CISA Silver bootstrap failed for artifact {candidate.artifact_id} "
                    f"after {created + reused} committed snapshots: {exc}"
                ) from exc
            issues.append(
                CisaBootstrapIssue(candidate.artifact_id, candidate.snapshot_id, str(exc))
            )
    return CisaBootstrapResult(
        dry_run,
        selection.available,
        len(selection.candidates),
        verified,
        planned,
        created,
        reused,
        record_count,
        tuple(issues),
    )


def bootstrap_cisa_silver(
    settings: Settings,
    *,
    dry_run: bool,
    limit: int | None = None,
    output_root: str | Path | None = None,
    local_store: RawReader | None = None,
) -> CisaBootstrapResult:
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            candidates = load_cisa_bootstrap_candidates(session)
    finally:
        engine.dispose()
    selection = select_cisa_bootstrap_candidates(candidates, limit=limit)
    return run_cisa_silver_bootstrap(
        selection,
        local_store=local_store or LocalRawArtifactStore(settings.raw_data_dir),
        output_root=output_root or settings.silver_data_dir,
        dry_run=dry_run,
    )


def _read_and_validate(candidate: CisaBootstrapCandidate, local_store: RawReader) -> bytes:
    content = local_store.read(candidate.local_uri)
    if len(content) != candidate.size_bytes:
        raise ValueError(
            f"CISA Raw size mismatch: expected {candidate.size_bytes}, got {len(content)}"
        )
    digest = calculate_sha256(content)
    if digest != candidate.sha256:
        raise ValueError(f"CISA Raw SHA-256 mismatch: expected {candidate.sha256}, got {digest}")
    catalog = parse_catalog_document(content)
    if len(catalog.records) != candidate.record_count:
        raise ValueError(
            f"CISA Raw record count mismatch: expected {candidate.record_count}, "
            f"parsed {len(catalog.records)}"
        )
    return content


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build CISA Silver snapshots from accepted local Raw artifacts."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=_positive_int)
    parser.add_argument("--output-root", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = bootstrap_cisa_silver(
            Settings(),
            dry_run=args.dry_run,
            limit=args.limit,
            output_root=args.output_root,
        )
    except Exception as exc:
        LOGGER.error("CISA Silver bootstrap failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 2 if result.issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
