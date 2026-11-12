"""Build historical EPSS Silver partitions from the local Raw manifest."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Protocol

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, aliased

from threatflow.config import Settings
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.transformation.epss_silver import (
    EpssSilverResult,
    transform_epss_bytes,
    verify_committed_epss_partition,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class EpssBootstrapCandidate:
    artifact_id: int
    sha256: str
    score_date: date
    record_count: int
    size_bytes: int
    acquired_at: datetime
    local_uri: str
    lineage_uri: str


@dataclass(frozen=True)
class EpssBootstrapSelection:
    available: int
    candidates: tuple[EpssBootstrapCandidate, ...]
    start_date: date | None
    end_date: date | None
    gap_dates: tuple[date, ...]


@dataclass(frozen=True)
class EpssBootstrapIssue:
    score_date: date
    source_sha256: str
    message: str


@dataclass(frozen=True)
class EpssBootstrapResult:
    dry_run: bool
    available: int
    selected: int
    verified: int
    planned: int
    created: int
    reused: int
    record_count: int
    start_date: date | None
    end_date: date | None
    gap_dates: tuple[date, ...]
    issues: tuple[EpssBootstrapIssue, ...]


class RawReader(Protocol):
    def read(self, artifact: RawArtifactRef | str) -> bytes: ...


SilverTransformer = Callable[..., EpssSilverResult]
CommittedPartitionVerifier = Callable[..., EpssSilverResult | None]


class EpssBootstrapItemError(RuntimeError):
    """One partition failed after earlier partitions may have committed safely."""


def load_epss_bootstrap_candidates(session: Session) -> list[EpssBootstrapCandidate]:
    """Load valid date-specific EPSS Raw inputs and their verified local locations."""
    local_location = aliased(RawArtifactLocation)
    s3_location = aliased(RawArtifactLocation)
    statement = (
        select(
            RawArtifact.id,
            RawArtifact.sha256,
            RawArtifact.requested_start,
            RawArtifact.record_count,
            RawArtifact.size_bytes,
            RawArtifact.first_acquired_at,
            local_location.uri.label("local_uri"),
            s3_location.uri.label("s3_uri"),
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
            RawArtifact.source == "epss",
            RawArtifact.request_mode == "score_date",
        )
        .order_by(RawArtifact.requested_start, RawArtifact.id)
    )

    candidates: list[EpssBootstrapCandidate] = []
    for row in session.execute(statement):
        if row.requested_start is None:
            raise ValueError(f"EPSS Raw artifact {row.id} is missing requested_start")
        if row.requested_start.tzinfo is None or row.requested_start.utcoffset() is None:
            raise ValueError(f"EPSS Raw artifact {row.id} has a naive requested_start")
        if row.first_acquired_at.tzinfo is None or row.first_acquired_at.utcoffset() is None:
            raise ValueError(f"EPSS Raw artifact {row.id} has a naive first_acquired_at")
        if row.record_count is None or row.record_count < 1:
            raise ValueError(f"EPSS Raw artifact {row.id} has no valid record_count")
        if not row.local_uri:
            raise FileNotFoundError(
                f"EPSS Raw artifact {row.id} has no verified local location"
            )
        candidates.append(
            EpssBootstrapCandidate(
                artifact_id=row.id,
                sha256=row.sha256,
                score_date=row.requested_start.astimezone(UTC).date(),
                record_count=row.record_count,
                size_bytes=row.size_bytes,
                acquired_at=row.first_acquired_at,
                local_uri=row.local_uri,
                lineage_uri=row.s3_uri or row.local_uri,
            )
        )
    return candidates


def select_epss_bootstrap_candidates(
    candidates: Iterable[EpssBootstrapCandidate],
    *,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int | None = None,
) -> EpssBootstrapSelection:
    """Validate manifest uniqueness, filter an inclusive range, and identify gaps."""
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("start_date must be on or before end_date")
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")

    ordered = sorted(candidates, key=lambda item: (item.score_date, item.artifact_id))
    by_date: dict[date, EpssBootstrapCandidate] = {}
    for candidate in ordered:
        previous = by_date.get(candidate.score_date)
        if previous is not None:
            raise ValueError(
                "multiple EPSS Raw artifacts target score_date "
                f"{candidate.score_date}: {previous.sha256}, {candidate.sha256}"
            )
        by_date[candidate.score_date] = candidate

    filtered = [
        candidate
        for candidate in ordered
        if (start_date is None or candidate.score_date >= start_date)
        and (end_date is None or candidate.score_date <= end_date)
    ]
    effective_start = start_date or (filtered[0].score_date if filtered else None)
    effective_end = end_date or (filtered[-1].score_date if filtered else None)
    gap_dates: tuple[date, ...] = ()
    if (
        effective_start is not None
        and effective_end is not None
        and effective_start <= effective_end
    ):
        present = {candidate.score_date for candidate in filtered}
        gap_dates = tuple(
            day
            for day in _date_range(effective_start, effective_end)
            if day not in present
        )

    available = len(filtered)
    if limit is not None:
        filtered = filtered[:limit]
    return EpssBootstrapSelection(
        available=available,
        candidates=tuple(filtered),
        start_date=effective_start,
        end_date=effective_end,
        gap_dates=gap_dates,
    )


def run_epss_silver_bootstrap(
    selection: EpssBootstrapSelection,
    *,
    local_store: RawReader,
    output_root: str | Path,
    dry_run: bool,
    transformer: SilverTransformer = transform_epss_bytes,
    committed_verifier: CommittedPartitionVerifier = verify_committed_epss_partition,
) -> EpssBootstrapResult:
    """Validate a plan or build its partitions sequentially and idempotently."""
    verified = planned = created = reused = record_count = 0
    issues: list[EpssBootstrapIssue] = []
    total = len(selection.candidates)

    for index, candidate in enumerate(selection.candidates, start=1):
        _log_progress(index, total, candidate.score_date, dry_run=dry_run)
        try:
            content = _read_and_validate(candidate, local_store)
            verified += 1
            if dry_run:
                committed = committed_verifier(
                    output_root=output_root,
                    score_date=candidate.score_date,
                    source_sha256=candidate.sha256,
                    expected_record_count=candidate.record_count,
                )
                if committed is None:
                    planned += 1
                else:
                    reused += 1
                record_count += candidate.record_count
                continue

            result = transformer(
                content,
                score_date=candidate.score_date,
                source_sha256=candidate.sha256,
                source_uri=candidate.lineage_uri,
                acquired_at=candidate.acquired_at,
                expected_record_count=candidate.record_count,
                output_root=output_root,
            )
            if result.created:
                created += 1
            else:
                reused += 1
            record_count += result.record_count
        except (OSError, TypeError, ValueError) as exc:
            if not dry_run:
                raise EpssBootstrapItemError(
                    f"EPSS Silver bootstrap failed for {candidate.score_date} "
                    f"({candidate.sha256}) after {created + reused} committed partitions: {exc}"
                ) from exc
            issues.append(
                EpssBootstrapIssue(
                    score_date=candidate.score_date,
                    source_sha256=candidate.sha256,
                    message=str(exc),
                )
            )

    return EpssBootstrapResult(
        dry_run=dry_run,
        available=selection.available,
        selected=total,
        verified=verified,
        planned=planned,
        created=created,
        reused=reused,
        record_count=record_count,
        start_date=selection.start_date,
        end_date=selection.end_date,
        gap_dates=selection.gap_dates,
        issues=tuple(issues),
    )


def bootstrap_epss_silver(
    settings: Settings,
    *,
    dry_run: bool,
    start_date: date | None = None,
    end_date: date | None = None,
    limit: int | None = None,
    output_root: str | Path | None = None,
    local_store: RawReader | None = None,
) -> EpssBootstrapResult:
    """Load the PostgreSQL plan and execute a local EPSS Silver bootstrap."""
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            candidates = load_epss_bootstrap_candidates(session)
    finally:
        engine.dispose()

    selection = select_epss_bootstrap_candidates(
        candidates,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    return run_epss_silver_bootstrap(
        selection,
        local_store=local_store or LocalRawArtifactStore(settings.raw_data_dir),
        output_root=output_root or settings.silver_data_dir,
        dry_run=dry_run,
    )


def _read_and_validate(candidate: EpssBootstrapCandidate, local_store: RawReader) -> bytes:
    content = local_store.read(candidate.local_uri)
    if len(content) != candidate.size_bytes:
        raise ValueError(
            f"EPSS Raw size mismatch: expected {candidate.size_bytes}, got {len(content)}"
        )
    digest = calculate_sha256(content)
    if digest != candidate.sha256:
        raise ValueError(
            f"EPSS Raw SHA-256 mismatch: expected {candidate.sha256}, got {digest}"
        )
    return content


def _date_range(start_date: date, end_date: date) -> Sequence[date]:
    return tuple(
        start_date + timedelta(days=offset)
        for offset in range((end_date - start_date).days + 1)
    )


def _log_progress(index: int, total: int, score_date: date, *, dry_run: bool) -> None:
    if index == 1 or index == total or index % 100 == 0:
        LOGGER.info(
            "EPSS Silver %s %d/%d: %s",
            "validation" if dry_run else "bootstrap",
            index,
            total,
            score_date,
        )


def _iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an ISO date in YYYY-MM-DD format") from exc


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build historical EPSS Silver partitions from verified local Raw files."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Verify Raw inputs and existing Silver partitions without writing files",
    )
    mode.add_argument(
        "--apply",
        action="store_true",
        help="Build or verify partitions sequentially",
    )
    parser.add_argument("--start-date", type=_iso_date, help="Inclusive YYYY-MM-DD")
    parser.add_argument("--end-date", type=_iso_date, help="Inclusive YYYY-MM-DD")
    parser.add_argument("--limit", type=_positive_int)
    parser.add_argument(
        "--output-root",
        type=Path,
        help="Override THREATFLOW_SILVER_DATA_DIR",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = bootstrap_epss_silver(
            Settings(),
            dry_run=args.dry_run,
            start_date=args.start_date,
            end_date=args.end_date,
            limit=args.limit,
            output_root=args.output_root,
        )
    except Exception as exc:
        LOGGER.error("EPSS Silver bootstrap failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 2 if result.issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
