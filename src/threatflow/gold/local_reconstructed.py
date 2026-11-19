"""Build explicitly labelled reconstructed Gold snapshots from local Silver Parquet."""

from __future__ import annotations

import argparse
import hashlib
import json
from bisect import bisect_right
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq
from pyspark.sql import SparkSession
from pyspark.storagelevel import StorageLevel

from threatflow.gold.local_publish import (
    LocalGoldPublishResult,
    canonical_input_fingerprint,
    publish_vulnerability_priority_local,
    reuse_committed_vulnerability_priority_local,
)
from threatflow.gold.vulnerability_priority import (
    POLICY_VERSION,
    build_vulnerability_priority_daily,
    build_vulnerability_priority_summary_daily,
)

SNAPSHOT_TYPE = "RECONSTRUCTED"
NVD_PROJECTION = "BEST_AVAILABLE_PUBLISHED_BASELINE"
DEFAULT_START_DATE = date(2025, 1, 27)
DEFAULT_END_DATE = date(2025, 12, 31)


class ReconstructionInputError(ValueError):
    """Raised when local Silver cannot support a requested reconstructed date."""


@dataclass(frozen=True)
class SilverArtifact:
    manifest_path: Path
    parquet_path: Path
    manifest: dict[str, Any]

    def reference(self, root: Path) -> dict[str, Any]:
        return {
            "manifest": str(self.manifest_path.relative_to(root)),
            "parquet": str(self.parquet_path.relative_to(root)),
            "sha256": self.manifest["parquet"]["sha256"],
            "record_count": self.manifest["record_count"],
        }


@dataclass(frozen=True)
class ReconstructedInputPlan:
    snapshot_date: date
    source_cutoff: datetime
    nvd: tuple[SilverArtifact, ...]
    cisa: SilverArtifact
    epss_current: SilverArtifact
    epss_previous: SilverArtifact

    def fingerprint_plan(self, silver_root: Path) -> dict[str, Any]:
        published_through = max(item.manifest["window_end"] for item in self.nvd)
        return {
            "nvd": {
                "projection": NVD_PROJECTION,
                "history_complete": False,
                "published_through": published_through,
                "artifacts": [item.reference(silver_root) for item in self.nvd],
            },
            "cisa": self.cisa.reference(silver_root),
            "epss_current": self.epss_current.reference(silver_root),
            "epss_previous": self.epss_previous.reference(silver_root),
        }


class LocalSilverCatalog:
    """Resolve committed Silver artifacts without inventing unavailable history."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._epss = self._index_epss()
        self._cisa = self._index_cisa_history()
        self._nvd = self._index_published_nvd()
        self._verified: set[Path] = set()

    def resolve(self, snapshot_date: date, *, verify: bool = True) -> ReconstructedInputPlan:
        current = self._epss.get(snapshot_date)
        previous = self._epss.get(snapshot_date - timedelta(days=7))
        if current is None or previous is None:
            raise ReconstructionInputError(
                f"EPSS is missing for {snapshot_date} or {snapshot_date - timedelta(days=7)}"
            )
        cutoff = datetime.combine(snapshot_date, time.max, tzinfo=UTC)
        observed = [value[0] for value in self._cisa]
        position = bisect_right(observed, cutoff) - 1
        if position < 0:
            raise ReconstructionInputError(
                f"no CISA git_history snapshot exists on or before {snapshot_date}"
            )
        plan = ReconstructedInputPlan(
            snapshot_date=snapshot_date,
            source_cutoff=cutoff,
            nvd=self._nvd,
            cisa=self._cisa[position][1],
            epss_current=current,
            epss_previous=previous,
        )
        if verify:
            for artifact in (*plan.nvd, plan.cisa, plan.epss_current, plan.epss_previous):
                if artifact.parquet_path not in self._verified:
                    _verify_artifact(artifact)
                    self._verified.add(artifact.parquet_path)
        return plan

    def _index_epss(self) -> dict[date, SilverArtifact]:
        result: dict[date, SilverArtifact] = {}
        for path in self.root.glob("epss_scores/score_date=*/_manifest.json"):
            artifact = _load_artifact(path, "epss_scores")
            score_date = date.fromisoformat(artifact.manifest["score_date"])
            if score_date in result:
                raise ReconstructionInputError(f"duplicate EPSS manifest for {score_date}")
            result[score_date] = artifact
        return result

    def _index_cisa_history(self) -> list[tuple[datetime, SilverArtifact]]:
        result = []
        pattern = "cisa_kev_snapshots/snapshot_kind=git_history/**/_manifest.json"
        for path in self.root.glob(pattern):
            artifact = _load_artifact(path, "cisa_kev_snapshots")
            observed = datetime.fromisoformat(
                artifact.manifest["snapshot"]["observed_at"].replace("Z", "+00:00")
            )
            result.append((observed, artifact))
        result.sort(key=lambda item: item[0])
        return result

    def _index_published_nvd(self) -> tuple[SilverArtifact, ...]:
        result = []
        for path in self.root.glob("nvd_cve_windows/mode=published/**/_manifest.json"):
            artifact = _load_artifact(path, "nvd_cve_windows")
            if artifact.manifest.get("mode") != "published":
                raise ReconstructionInputError(f"non-published NVD manifest at {path}")
            result.append(artifact)
        result.sort(key=lambda item: item.manifest["window_start"])
        if not result:
            raise ReconstructionInputError("no published NVD Silver windows found")
        return tuple(result)


def build_reconstructed_range(
    *,
    silver_root: str | Path,
    output_root: str | Path,
    start_date: date,
    end_date: date,
    dry_run: bool = True,
    limit: int | None = None,
) -> list[LocalGoldPublishResult | dict[str, Any]]:
    """Plan or publish inclusive daily reconstructed snapshots."""
    if start_date > end_date:
        raise ValueError("start_date must not be after end_date")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    catalog = LocalSilverCatalog(silver_root)
    dates = [
        start_date + timedelta(days=offset)
        for offset in range((end_date - start_date).days + 1)
    ]
    if limit is not None:
        dates = dates[:limit]
    plans = [catalog.resolve(day, verify=not dry_run) for day in dates]
    if dry_run:
        return [_planned_result(plan, catalog.root, output_root) for plan in plans]

    results: list[LocalGoldPublishResult | dict[str, Any]] = []
    pending: list[tuple[ReconstructedInputPlan, dict[str, Any]]] = []
    for plan in plans:
        input_plan = plan.fingerprint_plan(catalog.root)
        reused = reuse_committed_vulnerability_priority_local(
            input_plan=input_plan,
            output_root=output_root,
            snapshot_date=plan.snapshot_date,
            source_cutoff=plan.source_cutoff,
        )
        if reused is not None:
            results.append(reused)
        else:
            pending.append((plan, input_plan))
    if not pending:
        return results

    spark = _spark_session()
    default_generated_at = datetime.now(UTC)
    nvd_paths = [str(item.parquet_path) for item in pending[0][0].nvd]
    nvd = spark.read.parquet(*nvd_paths).persist(StorageLevel.DISK_ONLY)
    try:
        for plan, input_plan in pending:
            fingerprint = canonical_input_fingerprint(
                input_plan,
                snapshot_date=plan.snapshot_date,
                source_cutoff=plan.source_cutoff,
                policy_version=POLICY_VERSION,
            )
            generated_at = _resume_generated_at(
                Path(output_root), plan.snapshot_date, fingerprint, default_generated_at
            )
            detail = build_vulnerability_priority_daily(
                nvd=nvd,
                cisa=spark.read.parquet(str(plan.cisa.parquet_path)),
                epss_current=spark.read.parquet(str(plan.epss_current.parquet_path)),
                epss_previous=spark.read.parquet(str(plan.epss_previous.parquet_path)),
                snapshot_date=plan.snapshot_date,
                source_cutoff=plan.source_cutoff,
                generated_at=generated_at,
                input_fingerprint=fingerprint,
                snapshot_type=SNAPSHOT_TYPE,
                nvd_history_complete=False,
            ).persist(StorageLevel.DISK_ONLY)
            summary = None
            try:
                detail.count()
                summary = build_vulnerability_priority_summary_daily(
                    detail,
                    snapshot_date=plan.snapshot_date,
                    generated_at=generated_at,
                    input_fingerprint=fingerprint,
                    snapshot_type=SNAPSHOT_TYPE,
                    nvd_history_complete=False,
                ).persist(StorageLevel.DISK_ONLY)
                summary.count()
                results.append(
                    publish_vulnerability_priority_local(
                        detail,
                        summary,
                        input_plan=input_plan,
                        output_root=output_root,
                        snapshot_date=plan.snapshot_date,
                        source_cutoff=plan.source_cutoff,
                        generated_at=generated_at,
                        snapshot_type=SNAPSHOT_TYPE,
                        nvd_history_complete=False,
                    )
                )
            finally:
                if summary is not None:
                    summary.unpersist()
                detail.unpersist()
    finally:
        nvd.unpersist()
        spark.stop()
    return results


def _resume_generated_at(
    output_root: Path,
    snapshot_date: date,
    fingerprint: str,
    default: datetime,
) -> datetime:
    run_path = (
        output_root
        / "vulnerability_priority_daily"
        / f"snapshot_date={snapshot_date.isoformat()}"
        / f"run_id={fingerprint}"
    )
    first_part = next(iter(sorted(run_path.glob("part-*.parquet"))), None)
    if first_part is None:
        return default
    values = pq.read_table(first_part, columns=["generated_at"])["generated_at"]
    if not len(values):
        return default
    value = values[0].as_py()
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _planned_result(
    plan: ReconstructedInputPlan,
    root: Path,
    output_root: str | Path,
) -> dict[str, Any]:
    input_plan = plan.fingerprint_plan(root)
    return {
        "status": "PLANNED",
        "snapshot_date": plan.snapshot_date.isoformat(),
        "snapshot_type": SNAPSHOT_TYPE,
        "nvd_history_complete": False,
        "cisa_observed_at": plan.cisa.manifest["snapshot"]["observed_at"],
        "epss_score_date": plan.epss_current.manifest["score_date"],
        "output_root": str(Path(output_root)),
        "input_fingerprint": canonical_input_fingerprint(
            input_plan,
            snapshot_date=plan.snapshot_date,
            source_cutoff=plan.source_cutoff,
            policy_version=POLICY_VERSION,
        ),
    }


def _load_artifact(manifest_path: Path, dataset: str) -> SilverArtifact:
    try:
        manifest = json.loads(manifest_path.read_text())
        parquet = manifest["parquet"]
        parquet_path = manifest_path.parent / parquet["file"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReconstructionInputError(f"invalid Silver manifest: {manifest_path}") from exc
    if manifest.get("dataset") != dataset:
        raise ReconstructionInputError(f"unexpected dataset in {manifest_path}")
    return SilverArtifact(manifest_path, parquet_path, manifest)


def _verify_artifact(artifact: SilverArtifact) -> None:
    if not artifact.parquet_path.is_file():
        raise ReconstructionInputError(f"missing Silver Parquet: {artifact.parquet_path}")
    expected = artifact.manifest["parquet"]
    if artifact.parquet_path.stat().st_size != expected["size_bytes"]:
        raise ReconstructionInputError(f"Silver Parquet size mismatch: {artifact.parquet_path}")
    digest = hashlib.sha256()
    with artifact.parquet_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected["sha256"]:
        raise ReconstructionInputError(f"Silver Parquet checksum mismatch: {artifact.parquet_path}")
    if pq.ParquetFile(artifact.parquet_path).metadata.num_rows != artifact.manifest["record_count"]:
        raise ReconstructionInputError(
            f"Silver Parquet row count mismatch: {artifact.parquet_path}"
        )


def _spark_session() -> SparkSession:
    return (
        SparkSession.builder.master("local[2]")
        .appName("threatflow-reconstructed-gold")
        .config("spark.sql.session.timeZone", "UTC")
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.sql.autoBroadcastJoinThreshold", "-1")
        .getOrCreate()
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--silver-root", default="data/silver")
    parser.add_argument("--output-root", default="data/gold")
    parser.add_argument("--start-date", type=date.fromisoformat, default=DEFAULT_START_DATE)
    parser.add_argument("--end-date", type=date.fromisoformat, default=DEFAULT_END_DATE)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--apply", action="store_true", help="write Gold; default is dry-run")
    args = parser.parse_args()
    results = build_reconstructed_range(
        silver_root=args.silver_root,
        output_root=args.output_root,
        start_date=args.start_date,
        end_date=args.end_date,
        dry_run=not args.apply,
        limit=args.limit,
    )
    print(json.dumps([_json_result(item) for item in results], indent=2, sort_keys=True))


def _json_result(item: LocalGoldPublishResult | dict[str, Any]) -> dict[str, Any]:
    if isinstance(item, dict):
        return item
    return {
        "status": item.status,
        "snapshot_date": item.snapshot_date.isoformat(),
        "input_fingerprint": item.input_fingerprint,
        "detail_path": item.detail_path,
        "summary_path": item.summary_path,
        "product_commit_path": item.product_commit_path,
        "quality": {
            "detail_count": item.quality.detail_count,
            "summary_count": item.quality.summary_count,
            "tier_counts": item.quality.tier_counts,
        },
    }


if __name__ == "__main__":
    main()
