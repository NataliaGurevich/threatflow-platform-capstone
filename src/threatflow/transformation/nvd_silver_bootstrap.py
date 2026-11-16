"""Build NVD Silver windows from verified local Raw pages and their PostgreSQL lineage."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Protocol

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, aliased

from threatflow.config import Settings
from threatflow.ingestion.nvd_parser import parse_response
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.transformation.nvd_silver import (
    NvdSilverPageInput,
    transform_nvd_window,
    verify_committed_nvd_partition,
)
from threatflow.transformation.nvd_window import (
    NvdWindowManifest,
    NvdWindowPage,
    encode_nvd_window_manifest,
    window_sha256,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class NvdBootstrapPage:
    artifact_id: int
    sha256: str
    mode: str
    requested_start: datetime
    requested_end: datetime
    page_start_index: int
    record_count: int
    size_bytes: int
    acquired_at: datetime
    local_uri: str


@dataclass(frozen=True)
class NvdBootstrapWindow:
    mode: str
    requested_start: datetime
    requested_end: datetime
    pages: tuple[NvdBootstrapPage, ...]


@dataclass(frozen=True)
class NvdBootstrapSelection:
    available: int
    windows: tuple[NvdBootstrapWindow, ...]
    start_date: date | None
    end_date: date | None


@dataclass(frozen=True)
class NvdBootstrapIssue:
    mode: str
    requested_start: datetime
    requested_end: datetime
    message: str


@dataclass(frozen=True)
class NvdBootstrapResult:
    dry_run: bool
    available: int
    selected: int
    verified: int
    planned: int
    created: int
    reused: int
    source_records: int
    silver_records: int
    start_date: date | None
    end_date: date | None
    issues: tuple[NvdBootstrapIssue, ...]


class RawReader(Protocol):
    def read(self, artifact: RawArtifactRef | str) -> bytes: ...


class NvdBootstrapWindowError(RuntimeError):
    """One window failed after earlier windows may have committed safely."""


def load_nvd_bootstrap_pages(session: Session) -> list[NvdBootstrapPage]:
    """Load NVD pages that retain enough lineage to reconstruct complete windows."""
    local_location = aliased(RawArtifactLocation)
    statement = (
        select(
            RawArtifact.id,
            RawArtifact.sha256,
            RawArtifact.request_mode,
            RawArtifact.requested_start,
            RawArtifact.requested_end,
            RawArtifact.page_start_index,
            RawArtifact.record_count,
            RawArtifact.size_bytes,
            RawArtifact.first_acquired_at,
            local_location.uri.label("local_uri"),
        )
        .outerjoin(
            local_location,
            (local_location.artifact_id == RawArtifact.id)
            & (local_location.backend == "local"),
        )
        .where(
            RawArtifact.source == "nvd",
            RawArtifact.request_mode.in_(["published", "modified"]),
            RawArtifact.extension == "json",
        )
        .order_by(
            RawArtifact.requested_start,
            RawArtifact.requested_end,
            RawArtifact.page_start_index,
            RawArtifact.id,
        )
    )
    pages = []
    for row in session.execute(statement):
        required = {
            "requested_start": row.requested_start,
            "requested_end": row.requested_end,
            "page_start_index": row.page_start_index,
            "record_count": row.record_count,
            "local_uri": row.local_uri,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise ValueError(f"NVD Raw artifact {row.id} is missing {', '.join(missing)}")
        if any(
            value.tzinfo is None or value.utcoffset() is None
            for value in (row.requested_start, row.requested_end, row.first_acquired_at)
        ):
            raise ValueError(f"NVD Raw artifact {row.id} has naive timestamps")
        pages.append(
            NvdBootstrapPage(
                row.id,
                row.sha256,
                row.request_mode,
                row.requested_start.astimezone(UTC),
                row.requested_end.astimezone(UTC),
                row.page_start_index,
                row.record_count,
                row.size_bytes,
                row.first_acquired_at.astimezone(UTC),
                row.local_uri,
            )
        )
    return pages


def select_nvd_bootstrap_windows(
    pages: Iterable[NvdBootstrapPage],
    *,
    start_date: date | None = None,
    end_date: date | None = None,
    mode: str | None = None,
    limit: int | None = None,
) -> NvdBootstrapSelection:
    """Group pages by exact request window and select overlapping calendar ranges."""
    if start_date is not None and end_date is not None and start_date > end_date:
        raise ValueError("start_date must be on or before end_date")
    if mode not in {None, "published", "modified"}:
        raise ValueError("mode must be published or modified")
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    grouped: dict[tuple[str, datetime, datetime], list[NvdBootstrapPage]] = {}
    for page in pages:
        if page.mode not in {"published", "modified"}:
            raise ValueError(f"unsupported NVD mode: {page.mode}")
        grouped.setdefault(
            (page.mode, page.requested_start, page.requested_end), []
        ).append(page)
    windows = []
    for (window_mode, requested_start, requested_end), grouped_pages in grouped.items():
        by_index: dict[int, NvdBootstrapPage] = {}
        for page in grouped_pages:
            prior = by_index.get(page.page_start_index)
            if prior is not None and prior.sha256 != page.sha256:
                raise ValueError(
                    f"conflicting NVD pages for {window_mode} {requested_start} "
                    f"startIndex={page.page_start_index}"
                )
            by_index[page.page_start_index] = page
        windows.append(
            NvdBootstrapWindow(
                window_mode,
                requested_start,
                requested_end,
                tuple(by_index[index] for index in sorted(by_index)),
            )
        )
    ordered = sorted(
        windows, key=lambda item: (item.requested_start, item.requested_end, item.mode)
    )
    filtered = [
        window
        for window in ordered
        if (mode is None or window.mode == mode)
        and (start_date is None or window.requested_end.date() >= start_date)
        and (end_date is None or window.requested_start.date() <= end_date)
    ]
    available = len(filtered)
    return NvdBootstrapSelection(
        available,
        tuple(filtered[:limit] if limit is not None else filtered),
        start_date,
        end_date,
    )


def run_nvd_silver_bootstrap(
    selection: NvdBootstrapSelection,
    *,
    local_store: RawReader,
    output_root: str | Path,
    dry_run: bool,
) -> NvdBootstrapResult:
    verified = planned = created = reused = source_records = silver_records = 0
    issues = []
    total = len(selection.windows)
    for index, candidate in enumerate(selection.windows, start=1):
        LOGGER.info(
            "NVD Silver %s %d/%d: %s %s -> %s",
            "validation" if dry_run else "bootstrap",
            index,
            total,
            candidate.mode,
            candidate.requested_start.isoformat(),
            candidate.requested_end.isoformat(),
        )
        try:
            window_content, page_inputs, total_results = _prepare_window(
                candidate, local_store
            )
            digest = calculate_sha256(window_content)
            verified += 1
            source_records += total_results
            committed = verify_committed_nvd_partition(
                output_root=output_root,
                window_content=window_content,
                window_sha256=digest,
            )
            if dry_run:
                if committed is None:
                    planned += 1
                else:
                    reused += 1
                    silver_records += committed.record_count
                continue
            result = transform_nvd_window(
                window_content,
                window_sha256=digest,
                window_uri=f"local-window://{digest}",
                window_version_id=None,
                pages=page_inputs,
                output_root=output_root,
            )
            created += int(result.created)
            reused += int(not result.created)
            silver_records += result.record_count
        except (OSError, TypeError, ValueError) as exc:
            if not dry_run:
                raise NvdBootstrapWindowError(
                    f"NVD Silver bootstrap failed for {candidate.mode} "
                    f"{candidate.requested_start.isoformat()} -> "
                    f"{candidate.requested_end.isoformat()} after {created + reused} "
                    f"committed windows: {exc}"
                ) from exc
            issues.append(
                NvdBootstrapIssue(
                    candidate.mode,
                    candidate.requested_start,
                    candidate.requested_end,
                    str(exc),
                )
            )
    return NvdBootstrapResult(
        dry_run,
        selection.available,
        total,
        verified,
        planned,
        created,
        reused,
        source_records,
        silver_records,
        selection.start_date,
        selection.end_date,
        tuple(issues),
    )


def bootstrap_nvd_silver(
    settings: Settings,
    *,
    dry_run: bool,
    start_date: date | None = None,
    end_date: date | None = None,
    mode: str | None = None,
    limit: int | None = None,
    output_root: str | Path | None = None,
) -> NvdBootstrapResult:
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            pages = load_nvd_bootstrap_pages(session)
    finally:
        engine.dispose()
    selection = select_nvd_bootstrap_windows(
        pages, start_date=start_date, end_date=end_date, mode=mode, limit=limit
    )
    return run_nvd_silver_bootstrap(
        selection,
        local_store=LocalRawArtifactStore(settings.raw_data_dir),
        output_root=output_root or settings.silver_data_dir,
        dry_run=dry_run,
    )


def _prepare_window(
    candidate: NvdBootstrapWindow, local_store: RawReader
) -> tuple[bytes, list[NvdSilverPageInput], int]:
    expected_index = 0
    expected_total = None
    page_inputs = []
    acquired_at = max(page.acquired_at for page in candidate.pages)
    for page in candidate.pages:
        content = local_store.read(page.local_uri)
        if len(content) != page.size_bytes or calculate_sha256(content) != page.sha256:
            raise ValueError(f"NVD Raw integrity mismatch for artifact {page.artifact_id}")
        metadata, records = parse_response(content)
        if (
            page.page_start_index != expected_index
            or metadata["startIndex"] != page.page_start_index
            or metadata["resultsPerPage"] != page.record_count
            or len(records) != page.record_count
        ):
            raise ValueError("NVD page manifest and pagination metadata disagree")
        if expected_total is None:
            expected_total = metadata["totalResults"]
        elif expected_total != metadata["totalResults"]:
            raise ValueError("NVD totalResults changed within a stored window")
        lineage = NvdWindowPage(
            page.page_start_index,
            page.record_count,
            page.sha256,
            None,
            None,
            None,
            page.size_bytes,
            "local",
            page.local_uri,
        )
        page_inputs.append(NvdSilverPageInput(lineage, content))
        expected_index += page.record_count
    if expected_total is None or expected_index != expected_total:
        raise ValueError(
            f"NVD window is incomplete: stored {expected_index}, expected {expected_total}"
        )
    manifest = NvdWindowManifest(
        1,
        "nvd",
        candidate.mode,  # type: ignore[arg-type]
        candidate.requested_start,
        candidate.requested_end,
        acquired_at,
        expected_total,
        tuple(item.lineage for item in page_inputs),
    )
    encoded = encode_nvd_window_manifest(manifest)
    assert window_sha256(manifest) == calculate_sha256(encoded)
    return encoded, page_inputs, expected_total


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
        description="Build NVD Silver windows from verified local Raw JSON pages."
    )
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--dry-run", action="store_true")
    action.add_argument("--apply", action="store_true")
    parser.add_argument("--start-date", type=_iso_date)
    parser.add_argument("--end-date", type=_iso_date)
    parser.add_argument("--mode", choices=["published", "modified"])
    parser.add_argument("--limit", type=_positive_int)
    parser.add_argument("--output-root", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = bootstrap_nvd_silver(
            Settings(),
            dry_run=args.dry_run,
            start_date=args.start_date,
            end_date=args.end_date,
            mode=args.mode,
            limit=args.limit,
            output_root=args.output_root,
        )
    except Exception as exc:
        LOGGER.error("NVD Silver bootstrap failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 2 if result.issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
