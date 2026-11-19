"""Immutable local publication for the vulnerability-priority Gold product."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal

import pyarrow.parquet as pq
from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from threatflow.gold.quality import GoldQualityReport, validate_vulnerability_priority_gold
from threatflow.gold.vulnerability_priority import GOLD_SCHEMA_VERSION, POLICY_VERSION

FINGERPRINT_VERSION = 1
MANIFEST_VERSION = 1
PARQUET_COMPRESSION = "zstd"
DETAIL_DATASET = "vulnerability_priority_daily"
SUMMARY_DATASET = "vulnerability_priority_summary_daily"
PRODUCT_NAME = "vulnerability_priority"

_INPUT_NAMES = {"nvd", "cisa", "epss_current", "epss_previous"}


class GoldPublishError(RuntimeError):
    """Raised when existing or newly written Gold output is invalid."""


class GoldPublishConflict(GoldPublishError):
    """Raised when a snapshot date is already committed with another fingerprint."""


@dataclass(frozen=True)
class ParquetFile:
    file: str
    sha256: str
    size_bytes: int
    record_count: int


@dataclass(frozen=True)
class LocalGoldPublishResult:
    status: Literal["PLANNED", "CREATED", "REUSED"]
    snapshot_date: date
    input_fingerprint: str
    detail_path: str
    summary_path: str
    product_commit_path: str
    quality: GoldQualityReport


def reuse_committed_vulnerability_priority_local(
    *,
    input_plan: Mapping[str, Any],
    output_root: str | Path,
    snapshot_date: date,
    source_cutoff: datetime,
    policy_version: str = POLICY_VERSION,
) -> LocalGoldPublishResult | None:
    """Verify and reuse a committed snapshot without rebuilding its Spark frames."""
    fingerprint = canonical_input_fingerprint(
        input_plan,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        policy_version=policy_version,
    )
    root = Path(output_root)
    run_id = f"run_id={fingerprint}"
    date_partition = f"snapshot_date={snapshot_date.isoformat()}"
    detail_path = root / DETAIL_DATASET / date_partition / run_id
    summary_path = root / SUMMARY_DATASET / date_partition / run_id
    product_commit_path = root / "_commits" / PRODUCT_NAME / date_partition / "_manifest.json"
    if not product_commit_path.exists():
        return None
    commit = _read_json(product_commit_path, "product commit")
    if commit.get("input_fingerprint") != fingerprint:
        raise GoldPublishConflict(
            f"Gold snapshot {snapshot_date} is already committed with fingerprint "
            f"{commit.get('input_fingerprint')}"
        )
    _verify_committed_product(root, commit, detail_path, summary_path)
    quality_data = commit.get("quality")
    if not isinstance(quality_data, dict):
        raise GoldPublishError("product commit has no quality report")
    quality = GoldQualityReport(
        detail_count=int(quality_data["detail_count"]),
        summary_count=int(quality_data["summary_count"]),
        tier_counts={str(k): int(v) for k, v in quality_data["tier_counts"].items()},
    )
    return LocalGoldPublishResult(
        status="REUSED",
        snapshot_date=snapshot_date,
        input_fingerprint=fingerprint,
        detail_path=str(detail_path),
        summary_path=str(summary_path),
        product_commit_path=str(product_commit_path),
        quality=quality,
    )


def canonical_input_fingerprint(
    input_plan: Mapping[str, Any],
    *,
    snapshot_date: date,
    source_cutoff: datetime,
    policy_version: str = POLICY_VERSION,
) -> str:
    """Return a stable SHA-256 identity independent of mapping and input-list order."""
    _validate_input_plan(input_plan)
    _require_aware(source_cutoff, "source_cutoff")
    document = {
        "fingerprint_version": FINGERPRINT_VERSION,
        "gold_schema_version": GOLD_SCHEMA_VERSION,
        "policy_version": policy_version,
        "snapshot_date": snapshot_date.isoformat(),
        "source_cutoff": _utc_text(source_cutoff),
        "inputs": _canonicalize(input_plan),
    }
    return hashlib.sha256(_canonical_json(document)).hexdigest()


def publish_vulnerability_priority_local(
    detail: DataFrame,
    summary: DataFrame,
    *,
    input_plan: Mapping[str, Any],
    output_root: str | Path,
    snapshot_date: date,
    source_cutoff: datetime,
    generated_at: datetime,
    policy_version: str = POLICY_VERSION,
    snapshot_type: str = "OBSERVED",
    nvd_history_complete: bool = True,
    dry_run: bool = False,
) -> LocalGoldPublishResult:
    """Validate and publish one immutable local Gold snapshot."""
    _require_aware(source_cutoff, "source_cutoff")
    _require_aware(generated_at, "generated_at")
    fingerprint = canonical_input_fingerprint(
        input_plan,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        policy_version=policy_version,
    )
    quality = validate_vulnerability_priority_gold(detail, summary)
    _assert_frame_identity(
        detail,
        summary,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        generated_at=generated_at,
        policy_version=policy_version,
        input_fingerprint=fingerprint,
        snapshot_type=snapshot_type,
        nvd_history_complete=nvd_history_complete,
    )

    root = Path(output_root)
    run_id = f"run_id={fingerprint}"
    date_partition = f"snapshot_date={snapshot_date.isoformat()}"
    detail_path = root / DETAIL_DATASET / date_partition / run_id
    summary_path = root / SUMMARY_DATASET / date_partition / run_id
    product_commit_path = (
        root / "_commits" / PRODUCT_NAME / date_partition / "_manifest.json"
    )
    result_args = {
        "snapshot_date": snapshot_date,
        "input_fingerprint": fingerprint,
        "detail_path": str(detail_path),
        "summary_path": str(summary_path),
        "product_commit_path": str(product_commit_path),
        "quality": quality,
    }
    if dry_run:
        return LocalGoldPublishResult(status="PLANNED", **result_args)

    if product_commit_path.exists():
        commit = _read_json(product_commit_path, "product commit")
        existing_fingerprint = commit.get("input_fingerprint")
        if existing_fingerprint != fingerprint:
            raise GoldPublishConflict(
                f"Gold snapshot {snapshot_date} is already committed with fingerprint "
                f"{existing_fingerprint}"
            )
        _verify_committed_product(root, commit, detail_path, summary_path)
        return LocalGoldPublishResult(status="REUSED", **result_args)

    detail_readback = _ensure_parquet_output(detail, detail_path)
    summary_readback = _ensure_parquet_output(summary, summary_path)
    readback_quality = validate_vulnerability_priority_gold(detail_readback, summary_readback)
    if readback_quality != quality:
        raise GoldPublishError("Gold Parquet readback quality report does not match source frames")
    effective_generated_at = _assert_frame_identity(
        detail_readback,
        summary_readback,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        generated_at=generated_at,
        policy_version=policy_version,
        input_fingerprint=fingerprint,
        snapshot_type=snapshot_type,
        nvd_history_complete=nvd_history_complete,
    )

    detail_files = _parquet_inventory(detail_path)
    summary_files = _parquet_inventory(summary_path)
    canonical_plan = _canonicalize(input_plan)
    detail_manifest = _dataset_manifest(
        dataset=DETAIL_DATASET,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        generated_at=effective_generated_at,
        policy_version=policy_version,
        fingerprint=fingerprint,
        record_count=quality.detail_count,
        files=detail_files,
        input_plan=canonical_plan,
        tier_counts=quality.tier_counts,
        snapshot_type=snapshot_type,
        nvd_history_complete=nvd_history_complete,
    )
    summary_manifest = _dataset_manifest(
        dataset=SUMMARY_DATASET,
        snapshot_date=snapshot_date,
        source_cutoff=source_cutoff,
        generated_at=effective_generated_at,
        policy_version=policy_version,
        fingerprint=fingerprint,
        record_count=quality.summary_count,
        files=summary_files,
        input_plan=canonical_plan,
        detail_record_count=quality.detail_count,
        tier_counts=quality.tier_counts,
        snapshot_type=snapshot_type,
        nvd_history_complete=nvd_history_complete,
    )
    detail_manifest_path = detail_path / "_manifest.json"
    summary_manifest_path = summary_path / "_manifest.json"
    _publish_json(detail_manifest_path, detail_manifest, "detail manifest")
    _publish_json(summary_manifest_path, summary_manifest, "summary manifest")

    product_commit = {
        "product": PRODUCT_NAME,
        "manifest_version": MANIFEST_VERSION,
        "gold_schema_version": GOLD_SCHEMA_VERSION,
        "policy_version": policy_version,
        "snapshot_date": snapshot_date.isoformat(),
        "snapshot_type": snapshot_type,
        "nvd_history_complete": nvd_history_complete,
        "source_cutoff": _utc_text(source_cutoff),
        "input_fingerprint": fingerprint,
        "status": "COMMITTED",
        "detail": _manifest_reference(root, detail_manifest_path),
        "summary": _manifest_reference(root, summary_manifest_path),
        "quality": asdict(quality),
        "generated_at": _utc_text(effective_generated_at),
        "committed_at": _utc_text(datetime.now(UTC)),
    }
    _publish_json(product_commit_path, product_commit, "product commit")
    return LocalGoldPublishResult(status="CREATED", **result_args)


def _ensure_parquet_output(frame: DataFrame, path: Path) -> DataFrame:
    if path.exists():
        if not path.is_dir():
            raise GoldPublishError(f"Gold output path is not a directory: {path}")
        return frame.sparkSession.read.parquet(str(path))

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_root = Path(tempfile.mkdtemp(prefix=f".{path.name}-", dir=path.parent))
    temporary_data = temporary_root / "data"
    try:
        (
            frame.write.mode("errorifexists")
            .option("compression", PARQUET_COMPRESSION)
            .parquet(str(temporary_data))
        )
        frame.sparkSession.read.parquet(str(temporary_data)).count()
        try:
            path.mkdir()
        except FileExistsError:
            return frame.sparkSession.read.parquet(str(path))
        for item in temporary_data.iterdir():
            shutil.move(str(item), path / item.name)
        return frame.sparkSession.read.parquet(str(path))
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def _dataset_manifest(
    *,
    dataset: str,
    snapshot_date: date,
    source_cutoff: datetime,
    generated_at: datetime,
    policy_version: str,
    fingerprint: str,
    record_count: int,
    files: list[ParquetFile],
    input_plan: Any,
    tier_counts: dict[str, int],
    snapshot_type: str,
    nvd_history_complete: bool,
    detail_record_count: int | None = None,
) -> dict[str, Any]:
    manifest: dict[str, Any] = {
        "dataset": dataset,
        "manifest_version": MANIFEST_VERSION,
        "schema_version": GOLD_SCHEMA_VERSION,
        "policy_version": policy_version,
        "snapshot_date": snapshot_date.isoformat(),
        "snapshot_type": snapshot_type,
        "nvd_history_complete": nvd_history_complete,
        "source_cutoff": _utc_text(source_cutoff),
        "input_fingerprint": fingerprint,
        "record_count": record_count,
        "tier_counts": tier_counts,
        "inputs": input_plan,
        "parquet": {
            "compression": PARQUET_COMPRESSION,
            "files": [asdict(item) for item in files],
        },
        "generated_at": _utc_text(generated_at),
        "committed_at": _utc_text(datetime.now(UTC)),
    }
    if detail_record_count is not None:
        manifest["detail_record_count"] = detail_record_count
    return manifest


def _verify_committed_product(
    root: Path,
    commit: Mapping[str, Any],
    expected_detail_path: Path,
    expected_summary_path: Path,
) -> None:
    if commit.get("status") != "COMMITTED":
        raise GoldPublishError("product commit status is not COMMITTED")
    for label, expected_path in (
        ("detail", expected_detail_path),
        ("summary", expected_summary_path),
    ):
        reference = commit.get(label)
        if not isinstance(reference, dict):
            raise GoldPublishError(f"product commit is missing {label} manifest reference")
        manifest_path = root / str(reference.get("path", ""))
        if manifest_path != expected_path / "_manifest.json":
            raise GoldPublishError(f"product commit {label} path is invalid")
        if _sha256_file(manifest_path) != reference.get("sha256"):
            raise GoldPublishError(f"product commit {label} manifest checksum mismatch")
        manifest = _read_json(manifest_path, f"{label} manifest")
        if manifest.get("input_fingerprint") != commit.get("input_fingerprint"):
            raise GoldPublishError(f"{label} manifest fingerprint does not match product commit")
        _verify_manifest_files(expected_path, manifest)


def _verify_manifest_files(directory: Path, manifest: Mapping[str, Any]) -> None:
    parquet = manifest.get("parquet")
    files = parquet.get("files") if isinstance(parquet, dict) else None
    if not isinstance(files, list) or not files:
        raise GoldPublishError(f"manifest has no Parquet files: {directory}")
    total = 0
    for item in files:
        if not isinstance(item, dict):
            raise GoldPublishError(f"manifest has invalid Parquet entry: {directory}")
        path = directory / str(item.get("file", ""))
        if not path.is_file():
            raise GoldPublishError(f"committed Parquet file is missing: {path}")
        if path.stat().st_size != item.get("size_bytes") or _sha256_file(path) != item.get(
            "sha256"
        ):
            raise GoldPublishError(f"committed Parquet file checksum or size mismatch: {path}")
        rows = pq.ParquetFile(path).metadata.num_rows
        if rows != item.get("record_count"):
            raise GoldPublishError(f"committed Parquet row count mismatch: {path}")
        total += rows
    if total != manifest.get("record_count"):
        raise GoldPublishError(f"manifest total row count mismatch: {directory}")


def _parquet_inventory(directory: Path) -> list[ParquetFile]:
    files = []
    for path in sorted(directory.glob("part-*.parquet")):
        files.append(
            ParquetFile(
                file=path.name,
                sha256=_sha256_file(path),
                size_bytes=path.stat().st_size,
                record_count=pq.ParquetFile(path).metadata.num_rows,
            )
        )
    if not files:
        raise GoldPublishError(f"no Parquet part files were written: {directory}")
    return files


def _manifest_reference(root: Path, path: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(root)),
        "sha256": _sha256_file(path),
    }


def _publish_json(path: Path, payload: Mapping[str, Any], label: str) -> None:
    encoded = _pretty_json(payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".manifest-", delete=False) as f:
            temporary_path = Path(f.name)
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            existing = _read_json(path, label)
            if _without_commit_time(existing) != _without_commit_time(dict(payload)):
                raise GoldPublishConflict(f"conflicting {label} already exists: {path}") from None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise GoldPublishError(f"invalid {label}: {path}") from exc
    if not isinstance(value, dict):
        raise GoldPublishError(f"invalid {label}: {path}")
    return value


def _assert_frame_identity(
    detail: DataFrame,
    summary: DataFrame,
    *,
    snapshot_date: date,
    source_cutoff: datetime,
    generated_at: datetime,
    policy_version: str,
    input_fingerprint: str,
    snapshot_type: str,
    nvd_history_complete: bool,
) -> datetime:
    for label, frame in (("detail", detail), ("summary", summary)):
        if label == "detail" and not frame.limit(1).count():
            continue
        mismatch = (
            ~F.col("snapshot_date").eqNullSafe(F.lit(snapshot_date).cast("date"))
            | ~F.col("generated_at").eqNullSafe(F.lit(generated_at).cast("timestamp"))
            | ~F.col("policy_version").eqNullSafe(F.lit(policy_version))
            | ~F.col("input_fingerprint").eqNullSafe(F.lit(input_fingerprint))
            | ~F.col("snapshot_type").eqNullSafe(F.lit(snapshot_type))
            | ~F.col("nvd_history_complete").eqNullSafe(F.lit(nvd_history_complete))
        )
        if label == "detail":
            mismatch = mismatch | ~F.col("source_cutoff").eqNullSafe(
                F.lit(source_cutoff).cast("timestamp")
            )
        if frame.where(mismatch).limit(1).count():
            raise GoldPublishError(f"{label} publication identity does not match publisher inputs")
    return generated_at


def _validate_input_plan(input_plan: Mapping[str, Any]) -> None:
    if set(input_plan) != _INPUT_NAMES:
        raise ValueError(
            "input_plan must contain exactly nvd, cisa, epss_current, and epss_previous"
        )
    try:
        _canonical_json(_canonicalize(input_plan))
    except (TypeError, ValueError) as exc:
        raise ValueError("input_plan must be canonical JSON data") from exc


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        items = [_canonicalize(item) for item in value]
        return sorted(items, key=_canonical_json)
    if value is None or isinstance(value, str | int | float | bool):
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _pretty_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _without_commit_time(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "committed_at"}


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
