"""Build one typed EPSS Silver Parquet partition from an accepted Raw artifact."""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pyarrow as pa
import pyarrow.parquet as pq

from threatflow.ingestion.epss_parser import parse_dataset
from threatflow.ingestion.epss_validation import validate_completeness
from threatflow.raw_storage import calculate_sha256

if TYPE_CHECKING:
    from threatflow.config import Settings

LOGGER = logging.getLogger(__name__)

DATASET_NAME = "epss_scores"
SCHEMA_VERSION = 1
TRANSFORM_VERSION = "1.0.0"
PARQUET_FILE_NAME = "epss.parquet"
MANIFEST_FILE_NAME = "_manifest.json"
PARQUET_COMPRESSION = "zstd"
PARQUET_COMPRESSION_LEVEL = 3
PARQUET_ROW_GROUP_SIZE = 100_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class EpssBronzeInput:
    sha256: str
    score_date: date
    record_count: int
    acquired_at: datetime
    read_uri: str
    lineage_uri: str


@dataclass(frozen=True)
class EpssSilverResult:
    dataset: str
    score_date: date
    source_sha256: str
    record_count: int
    parquet_path: str
    manifest_path: str
    parquet_sha256: str
    parquet_size_bytes: int
    created: bool


def epss_silver_schema(
    *,
    source_sha256: str,
    score_date: date,
    record_count: int,
) -> pa.Schema:
    """Return the versioned EPSS Silver Arrow schema with deterministic lineage metadata."""
    metadata = {
        b"threatflow.dataset": DATASET_NAME.encode(),
        b"threatflow.schema_version": str(SCHEMA_VERSION).encode(),
        b"threatflow.transform_version": TRANSFORM_VERSION.encode(),
        b"threatflow.source_sha256": source_sha256.encode(),
        b"threatflow.score_date": score_date.isoformat().encode(),
        b"threatflow.record_count": str(record_count).encode(),
    }
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("score_date", pa.date32(), nullable=False),
            pa.field("epss_score", pa.float64(), nullable=False),
            pa.field("percentile", pa.float64(), nullable=False),
            pa.field("source_sha256", pa.string(), nullable=False),
        ],
        metadata=metadata,
    )


def transform_epss_bytes(
    content: bytes,
    *,
    score_date: date,
    source_sha256: str,
    source_uri: str,
    acquired_at: datetime,
    expected_record_count: int | None,
    output_root: str | Path,
    source_version_id: str | None = None,
) -> EpssSilverResult:
    """Validate exact EPSS Raw bytes and publish one committed Parquet partition."""
    if not _SHA256.fullmatch(source_sha256):
        raise ValueError("source_sha256 must be 64 lowercase hexadecimal characters")
    actual_sha256 = calculate_sha256(content)
    if actual_sha256 != source_sha256:
        raise ValueError(
            f"EPSS Raw SHA-256 mismatch: expected {source_sha256}, got {actual_sha256}"
        )
    if expected_record_count is not None and expected_record_count < 1:
        raise ValueError("expected_record_count must be at least 1")
    if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
        raise ValueError("acquired_at must be timezone-aware")

    partition_dir = (
        Path(output_root) / DATASET_NAME / f"score_date={score_date.isoformat()}"
    )
    parquet_path = partition_dir / PARQUET_FILE_NAME
    manifest_path = partition_dir / MANIFEST_FILE_NAME
    if manifest_path.exists() and expected_record_count is not None:
        return _reuse_committed_partition(
            parquet_path,
            manifest_path,
            score_date=score_date,
            source_sha256=source_sha256,
            expected_record_count=expected_record_count,
        )

    records = parse_dataset(content, score_date)
    if expected_record_count is not None and len(records) != expected_record_count:
        raise ValueError(
            f"EPSS manifest count mismatch: expected {expected_record_count}, "
            f"parsed {len(records)}"
        )
    validate_completeness(len(records), score_date)
    record_count = len(records)

    if manifest_path.exists():
        return _reuse_committed_partition(
            parquet_path,
            manifest_path,
            score_date=score_date,
            source_sha256=source_sha256,
            expected_record_count=record_count,
        )

    schema = epss_silver_schema(
        source_sha256=source_sha256,
        score_date=score_date,
        record_count=record_count,
    )
    partition_dir.mkdir(parents=True, exist_ok=True)
    if parquet_path.exists():
        parquet_sha256, parquet_size = _verify_parquet(
            parquet_path,
            schema=schema,
            expected_record_count=record_count,
        )
        _publish_manifest(
            manifest_path,
            _manifest_payload(
                score_date=score_date,
                source_sha256=source_sha256,
                source_uri=source_uri,
                acquired_at=acquired_at,
                record_count=record_count,
                parquet_sha256=parquet_sha256,
                parquet_size_bytes=parquet_size,
                source_version_id=source_version_id,
            ),
        )
        return EpssSilverResult(
            DATASET_NAME,
            score_date,
            source_sha256,
            record_count,
            str(parquet_path),
            str(manifest_path),
            parquet_sha256,
            parquet_size,
            False,
        )

    table = _records_to_table(records, schema, source_sha256)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=partition_dir,
            prefix=".epss-",
            suffix=".parquet.tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
        pq.write_table(
            table,
            temporary_path,
            compression=PARQUET_COMPRESSION,
            compression_level=PARQUET_COMPRESSION_LEVEL,
            use_dictionary=["cve_id", "source_sha256"],
            write_statistics=True,
            row_group_size=PARQUET_ROW_GROUP_SIZE,
            version="2.6",
            write_page_checksum=True,
        )
        _fsync(temporary_path)
        parquet_sha256, parquet_size = _verify_parquet(
            temporary_path,
            schema=schema,
            expected_record_count=record_count,
        )
        try:
            os.link(temporary_path, parquet_path)
        except FileExistsError:
            existing_sha256, existing_size = _verify_parquet(
                parquet_path,
                schema=schema,
                expected_record_count=record_count,
            )
            if (existing_sha256, existing_size) != (parquet_sha256, parquet_size):
                raise FileExistsError(
                    f"conflicting EPSS Silver partition already exists: {parquet_path}"
                ) from None
            parquet_sha256, parquet_size = existing_sha256, existing_size
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    _publish_manifest(
        manifest_path,
        _manifest_payload(
            score_date=score_date,
            source_sha256=source_sha256,
            source_uri=source_uri,
            acquired_at=acquired_at,
            record_count=record_count,
            parquet_sha256=parquet_sha256,
            parquet_size_bytes=parquet_size,
            source_version_id=source_version_id,
        ),
    )
    return EpssSilverResult(
        DATASET_NAME,
        score_date,
        source_sha256,
        record_count,
        str(parquet_path),
        str(manifest_path),
        parquet_sha256,
        parquet_size,
        True,
    )


def build_epss_silver(
    settings: Settings,
    *,
    sha256: str,
    output_root: str | Path | None = None,
) -> EpssSilverResult:
    """Resolve one accepted EPSS artifact from PostgreSQL and transform its local bytes."""
    from threatflow.local_raw_storage import LocalRawArtifactStore

    artifact = _load_bronze_input(settings, sha256)
    content = LocalRawArtifactStore(settings.raw_data_dir).read(artifact.read_uri)
    return transform_epss_bytes(
        content,
        score_date=artifact.score_date,
        source_sha256=artifact.sha256,
        source_uri=artifact.lineage_uri,
        acquired_at=artifact.acquired_at,
        expected_record_count=artifact.record_count,
        output_root=output_root or settings.silver_data_dir,
    )


def verify_committed_epss_partition(
    *,
    output_root: str | Path,
    score_date: date,
    source_sha256: str,
    expected_record_count: int,
) -> EpssSilverResult | None:
    """Verify a committed partition, or return ``None`` when it is not committed."""
    partition_dir = (
        Path(output_root) / DATASET_NAME / f"score_date={score_date.isoformat()}"
    )
    manifest_path = partition_dir / MANIFEST_FILE_NAME
    if not manifest_path.exists():
        return None
    return _reuse_committed_partition(
        partition_dir / PARQUET_FILE_NAME,
        manifest_path,
        score_date=score_date,
        source_sha256=source_sha256,
        expected_record_count=expected_record_count,
    )


def _load_bronze_input(settings: Settings, sha256: str) -> EpssBronzeInput:
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session, selectinload

    from threatflow.models.raw_artifact import RawArtifact
    from threatflow.repository.raw_artifact_repository import artifact_location_uri

    if not _SHA256.fullmatch(sha256):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    engine = create_engine(settings.database_url)
    try:
        with Session(engine) as session:
            artifact = session.scalar(
                select(RawArtifact)
                .options(selectinload(RawArtifact.locations))
                .where(
                    RawArtifact.source == "epss",
                    RawArtifact.sha256 == sha256,
                    RawArtifact.request_mode == "score_date",
                )
            )
            if artifact is None:
                raise FileNotFoundError(
                    f"accepted EPSS Raw artifact is not in the manifest: {sha256}"
                )
            if artifact.requested_start is None or artifact.record_count is None:
                raise ValueError("EPSS Raw artifact is missing score date or record count lineage")
            if (
                artifact.requested_start.tzinfo is None
                or artifact.requested_start.utcoffset() is None
            ):
                raise ValueError("EPSS requested_start must be timezone-aware")
            read_uri = artifact_location_uri(artifact, "local")
            try:
                lineage_uri = artifact_location_uri(artifact, "s3")
            except FileNotFoundError:
                lineage_uri = read_uri
            return EpssBronzeInput(
                sha256=artifact.sha256,
                score_date=artifact.requested_start.astimezone(UTC).date(),
                record_count=artifact.record_count,
                acquired_at=artifact.first_acquired_at,
                read_uri=read_uri,
                lineage_uri=lineage_uri,
            )
    finally:
        engine.dispose()


def _records_to_table(
    records: list[dict[str, Any]],
    schema: pa.Schema,
    source_sha256: str,
) -> pa.Table:
    return pa.Table.from_arrays(
        [
            pa.array((record["cve_id"] for record in records), type=pa.string()),
            pa.array((record["score_date"] for record in records), type=pa.date32()),
            pa.array((record["epss_score"] for record in records), type=pa.float64()),
            pa.array((record["percentile"] for record in records), type=pa.float64()),
            pa.array((source_sha256 for _ in records), type=pa.string()),
        ],
        schema=schema,
    )


def _manifest_payload(
    *,
    score_date: date,
    source_sha256: str,
    source_uri: str,
    acquired_at: datetime,
    record_count: int,
    parquet_sha256: str,
    parquet_size_bytes: int,
    source_version_id: str | None = None,
) -> dict[str, Any]:
    source = {
        "name": "epss",
        "sha256": source_sha256,
        "uri": source_uri,
        "acquired_at": acquired_at.astimezone(UTC).isoformat(),
    }
    if source_version_id is not None:
        source["version_id"] = source_version_id
    return {
        "dataset": DATASET_NAME,
        "schema_version": SCHEMA_VERSION,
        "transform_version": TRANSFORM_VERSION,
        "score_date": score_date.isoformat(),
        "record_count": record_count,
        "source": source,
        "parquet": {
            "file": PARQUET_FILE_NAME,
            "sha256": parquet_sha256,
            "size_bytes": parquet_size_bytes,
            "compression": PARQUET_COMPRESSION,
        },
        "committed_at": datetime.now(UTC).isoformat(),
    }


def _publish_manifest(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent,
            prefix=".manifest-",
            suffix=".json.tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(encoded)
            temporary.flush()
            os.fsync(temporary.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            existing = json.loads(path.read_text())
            if _manifest_identity(existing) != _manifest_identity(payload):
                raise FileExistsError(
                    f"conflicting EPSS Silver manifest already exists: {path}"
                ) from None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _reuse_committed_partition(
    parquet_path: Path,
    manifest_path: Path,
    *,
    score_date: date,
    source_sha256: str,
    expected_record_count: int,
) -> EpssSilverResult:
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid EPSS Silver manifest: {manifest_path}") from exc
    expected_identity = (
        DATASET_NAME,
        SCHEMA_VERSION,
        TRANSFORM_VERSION,
        score_date.isoformat(),
        expected_record_count,
        source_sha256,
    )
    if _manifest_identity(manifest) != expected_identity:
        raise FileExistsError(
            f"conflicting EPSS Silver partition already exists: {manifest_path.parent}"
        )
    schema = epss_silver_schema(
        source_sha256=source_sha256,
        score_date=score_date,
        record_count=expected_record_count,
    )
    parquet_sha256, parquet_size = _verify_parquet(
        parquet_path,
        schema=schema,
        expected_record_count=expected_record_count,
    )
    parquet_manifest = manifest.get("parquet", {})
    if (
        parquet_manifest.get("sha256") != parquet_sha256
        or parquet_manifest.get("size_bytes") != parquet_size
    ):
        raise ValueError("EPSS Silver Parquet does not match its commit manifest")
    return EpssSilverResult(
        DATASET_NAME,
        score_date,
        source_sha256,
        expected_record_count,
        str(parquet_path),
        str(manifest_path),
        parquet_sha256,
        parquet_size,
        False,
    )


def _manifest_identity(manifest: dict[str, Any]) -> tuple[Any, ...]:
    source = manifest.get("source", {})
    return (
        manifest.get("dataset"),
        manifest.get("schema_version"),
        manifest.get("transform_version"),
        manifest.get("score_date"),
        manifest.get("record_count"),
        source.get("sha256"),
    )


def _verify_parquet(
    path: Path,
    *,
    schema: pa.Schema,
    expected_record_count: int,
) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(f"EPSS Silver Parquet is missing: {path}")
    parquet = pq.ParquetFile(path)
    if parquet.metadata.num_rows != expected_record_count:
        raise ValueError(
            f"EPSS Silver row count mismatch: expected {expected_record_count}, "
            f"got {parquet.metadata.num_rows}"
        )
    if not parquet.schema_arrow.equals(schema, check_metadata=True):
        raise ValueError("EPSS Silver Parquet schema or lineage metadata mismatch")
    return _file_sha256(path), path.stat().st_size


def _file_sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync(path: Path) -> None:
    with path.open("rb") as artifact:
        os.fsync(artifact.fileno())


def _sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "must contain exactly 64 lowercase hexadecimal characters"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build one committed EPSS Silver Parquet partition from local Raw storage."
    )
    parser.add_argument("--sha256", required=True, type=_sha256)
    parser.add_argument(
        "--output-root",
        type=Path,
        help="Override THREATFLOW_SILVER_DATA_DIR",
    )
    return parser


def main() -> int:
    from threatflow.config import Settings

    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = build_epss_silver(
            Settings(),
            sha256=args.sha256,
            output_root=args.output_root,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        LOGGER.error("EPSS Silver transformation failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
