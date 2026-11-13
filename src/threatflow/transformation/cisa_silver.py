"""Build one immutable typed CISA KEV Silver snapshot from validated Raw bytes."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pyarrow as pa
import pyarrow.parquet as pq

from threatflow.ingestion.cisa_parser import ParsedCatalog, parse_catalog_document
from threatflow.raw_storage import calculate_sha256

DATASET_NAME = "cisa_kev_snapshots"
SCHEMA_VERSION = 1
TRANSFORM_VERSION = "1.0.0"
PARQUET_FILE_NAME = "cisa_kev.parquet"
MANIFEST_FILE_NAME = "_manifest.json"
PARQUET_COMPRESSION = "zstd"
SnapshotKind = Literal["snapshot", "git_history"]

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class CisaSilverResult:
    dataset: str
    snapshot_kind: SnapshotKind
    snapshot_id: str
    source_sha256: str
    record_count: int
    parquet_path: str
    manifest_path: str
    parquet_sha256: str
    parquet_size_bytes: int
    created: bool


def transform_cisa_bytes(
    content: bytes,
    *,
    snapshot_kind: SnapshotKind,
    source_sha256: str,
    source_uri: str,
    acquired_at: datetime,
    output_root: str | Path,
    source_revision: str | None = None,
    source_version_id: str | None = None,
    snapshot_observed_at: datetime | None = None,
    expected_record_count: int | None = None,
) -> CisaSilverResult:
    """Validate exact CISA bytes and atomically commit one local Silver snapshot."""
    _validate_lineage(
        content,
        snapshot_kind=snapshot_kind,
        source_sha256=source_sha256,
        source_revision=source_revision,
        acquired_at=acquired_at,
        expected_record_count=expected_record_count,
    )
    catalog = parse_catalog_document(content)
    observed_at = snapshot_observed_at or acquired_at
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("snapshot_observed_at must be timezone-aware")
    record_count = len(catalog.records)
    if expected_record_count is not None and record_count != expected_record_count:
        raise ValueError(
            f"CISA manifest count mismatch: expected {expected_record_count}, parsed {record_count}"
        )

    snapshot_id = source_revision if snapshot_kind == "git_history" else source_sha256
    assert snapshot_id is not None
    partition = (
        Path(output_root)
        / DATASET_NAME
        / f"snapshot_kind={snapshot_kind}"
        / f"snapshot_id={snapshot_id}"
    )
    parquet_path = partition / PARQUET_FILE_NAME
    manifest_path = partition / MANIFEST_FILE_NAME
    if manifest_path.exists():
        return _reuse(
            parquet_path,
            manifest_path,
            snapshot_kind=snapshot_kind,
            snapshot_id=snapshot_id,
            source_sha256=source_sha256,
            record_count=record_count,
        )

    schema = cisa_silver_schema(
        snapshot_kind=snapshot_kind,
        snapshot_id=snapshot_id,
        source_sha256=source_sha256,
        record_count=record_count,
    )
    partition.mkdir(parents=True, exist_ok=True)
    if not parquet_path.exists():
        _write_parquet(parquet_path, _records_to_table(catalog, schema, observed_at, source_sha256))
    parquet_sha256, parquet_size = _verify_parquet(
        parquet_path, schema=schema, record_count=record_count
    )
    payload = _manifest_payload(
        catalog,
        snapshot_kind=snapshot_kind,
        snapshot_id=snapshot_id,
        source_sha256=source_sha256,
        source_uri=source_uri,
        acquired_at=acquired_at,
        snapshot_observed_at=observed_at,
        source_revision=source_revision,
        source_version_id=source_version_id,
        parquet_sha256=parquet_sha256,
        parquet_size=parquet_size,
    )
    _publish_manifest(manifest_path, payload)
    return CisaSilverResult(
        DATASET_NAME,
        snapshot_kind,
        snapshot_id,
        source_sha256,
        record_count,
        str(parquet_path),
        str(manifest_path),
        parquet_sha256,
        parquet_size,
        True,
    )


def cisa_silver_schema(
    *, snapshot_kind: SnapshotKind, snapshot_id: str, source_sha256: str, record_count: int
) -> pa.Schema:
    metadata = {
        b"threatflow.dataset": DATASET_NAME.encode(),
        b"threatflow.schema_version": str(SCHEMA_VERSION).encode(),
        b"threatflow.transform_version": TRANSFORM_VERSION.encode(),
        b"threatflow.snapshot_kind": snapshot_kind.encode(),
        b"threatflow.snapshot_id": snapshot_id.encode(),
        b"threatflow.source_sha256": source_sha256.encode(),
        b"threatflow.record_count": str(record_count).encode(),
    }
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("vendor_project", pa.string(), nullable=False),
            pa.field("product", pa.string(), nullable=False),
            pa.field("vulnerability_name", pa.string(), nullable=False),
            pa.field("date_added", pa.date32(), nullable=False),
            pa.field("short_description", pa.string(), nullable=False),
            pa.field("required_action", pa.string(), nullable=False),
            pa.field("due_date", pa.date32(), nullable=False),
            pa.field("known_ransomware_campaign_use", pa.string(), nullable=False),
            pa.field("notes", pa.string()),
            pa.field("cwes", pa.list_(pa.string())),
            pa.field("catalog_version", pa.string()),
            pa.field("catalog_released_at", pa.timestamp("us", tz="UTC")),
            pa.field("snapshot_observed_at", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("snapshot_kind", pa.string(), nullable=False),
            pa.field("source_revision", pa.string()),
            pa.field("source_sha256", pa.string(), nullable=False),
        ],
        metadata=metadata,
    )


def verify_committed_cisa_partition(
    *,
    output_root: str | Path,
    snapshot_kind: SnapshotKind,
    snapshot_id: str,
    source_sha256: str,
    expected_record_count: int,
) -> CisaSilverResult | None:
    """Verify a committed local CISA partition, or return None when absent."""
    partition = (
        Path(output_root)
        / DATASET_NAME
        / f"snapshot_kind={snapshot_kind}"
        / f"snapshot_id={snapshot_id}"
    )
    manifest_path = partition / MANIFEST_FILE_NAME
    if not manifest_path.exists():
        return None
    return _reuse(
        partition / PARQUET_FILE_NAME,
        manifest_path,
        snapshot_kind=snapshot_kind,
        snapshot_id=snapshot_id,
        source_sha256=source_sha256,
        record_count=expected_record_count,
    )


def _validate_lineage(
    content: bytes,
    *,
    snapshot_kind: str,
    source_sha256: str,
    source_revision: str | None,
    acquired_at: datetime,
    expected_record_count: int | None,
) -> None:
    if snapshot_kind not in ("snapshot", "git_history"):
        raise ValueError("snapshot_kind must be snapshot or git_history")
    if not _SHA256.fullmatch(source_sha256):
        raise ValueError("source_sha256 must be 64 lowercase hexadecimal characters")
    if calculate_sha256(content) != source_sha256:
        raise ValueError("CISA Raw SHA-256 mismatch")
    if acquired_at.tzinfo is None or acquired_at.utcoffset() is None:
        raise ValueError("acquired_at must be timezone-aware")
    if snapshot_kind == "git_history" and not _GIT_SHA.fullmatch(source_revision or ""):
        raise ValueError("git_history requires a 40-character lowercase source_revision")
    if snapshot_kind == "snapshot" and source_revision is not None:
        raise ValueError("snapshot must not have a source_revision")
    if expected_record_count is not None and expected_record_count < 1:
        raise ValueError("expected_record_count must be at least 1")


def _records_to_table(
    catalog: ParsedCatalog, schema: pa.Schema, acquired_at: datetime, source_sha256: str
) -> pa.Table:
    released = catalog.date_released
    if released is not None:
        if released.tzinfo is None or released.utcoffset() is None:
            raise ValueError("CISA dateReleased must be timezone-aware")
        released = released.astimezone(UTC)
    rows = [
        {
            **record,
            "catalog_version": catalog.catalog_version,
            "catalog_released_at": released,
            "snapshot_observed_at": acquired_at.astimezone(UTC),
            "snapshot_kind": schema.metadata[b"threatflow.snapshot_kind"].decode(),
            "source_revision": (
                schema.metadata[b"threatflow.snapshot_id"].decode()
                if schema.metadata[b"threatflow.snapshot_kind"] == b"git_history"
                else None
            ),
            "source_sha256": source_sha256,
        }
        for record in catalog.records
    ]
    return pa.Table.from_pylist(rows, schema=schema)


def _write_parquet(path: Path, table: pa.Table) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".cisa-", delete=False) as temp:
            temporary_path = Path(temp.name)
        pq.write_table(
            table,
            temporary_path,
            compression=PARQUET_COMPRESSION,
            compression_level=3,
            use_dictionary=True,
            write_statistics=True,
            version="2.6",
            write_page_checksum=True,
        )
        with temporary_path.open("rb") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            pass
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _verify_parquet(path: Path, *, schema: pa.Schema, record_count: int) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(f"CISA Silver Parquet is missing: {path}")
    table = pq.read_table(path)
    if table.schema != schema or table.num_rows != record_count:
        raise ValueError(f"CISA Silver Parquet failed schema or row-count verification: {path}")
    return calculate_sha256(path.read_bytes()), path.stat().st_size


def _manifest_payload(
    catalog: ParsedCatalog,
    *,
    snapshot_kind: SnapshotKind,
    snapshot_id: str,
    source_sha256: str,
    source_uri: str,
    acquired_at: datetime,
    snapshot_observed_at: datetime,
    source_revision: str | None,
    source_version_id: str | None,
    parquet_sha256: str,
    parquet_size: int,
) -> dict[str, Any]:
    source: dict[str, Any] = {
        "name": "cisa_kev",
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
        "snapshot": {
            "kind": snapshot_kind,
            "id": snapshot_id,
            "source_revision": source_revision,
            "catalog_version": catalog.catalog_version,
            "catalog_released_at": (
                catalog.date_released.astimezone(UTC).isoformat()
                if catalog.date_released is not None
                else None
            ),
            "observed_at": snapshot_observed_at.astimezone(UTC).isoformat(),
        },
        "record_count": len(catalog.records),
        "source": source,
        "parquet": {
            "file": PARQUET_FILE_NAME,
            "sha256": parquet_sha256,
            "size_bytes": parquet_size,
            "compression": PARQUET_COMPRESSION,
        },
        "committed_at": datetime.now(UTC).isoformat(),
    }


def _publish_manifest(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".manifest-", delete=False
        ) as temp:
            temporary_path = Path(temp.name)
            temp.write(encoded)
            temp.flush()
            os.fsync(temp.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            existing = json.loads(path.read_text())
            if _manifest_identity(existing) != _manifest_identity(payload):
                raise FileExistsError(
                    f"conflicting CISA Silver manifest already exists: {path}"
                ) from None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _manifest_identity(value: dict[str, Any]) -> tuple[Any, ...]:
    return (
        value.get("dataset"),
        value.get("schema_version"),
        value.get("transform_version"),
        value.get("snapshot", {}).get("kind"),
        value.get("snapshot", {}).get("id"),
        value.get("source", {}).get("sha256"),
        value.get("record_count"),
        value.get("parquet", {}).get("sha256"),
    )


def _reuse(
    parquet_path: Path,
    manifest_path: Path,
    *,
    snapshot_kind: SnapshotKind,
    snapshot_id: str,
    source_sha256: str,
    record_count: int,
) -> CisaSilverResult:
    manifest = json.loads(manifest_path.read_text())
    expected = (DATASET_NAME, snapshot_kind, snapshot_id, source_sha256, record_count)
    actual = (
        manifest.get("dataset"),
        manifest.get("snapshot", {}).get("kind"),
        manifest.get("snapshot", {}).get("id"),
        manifest.get("source", {}).get("sha256"),
        manifest.get("record_count"),
    )
    if actual != expected:
        raise FileExistsError(f"conflicting CISA Silver partition: {manifest_path.parent}")
    parquet = manifest.get("parquet", {})
    digest = parquet.get("sha256")
    size = parquet.get("size_bytes")
    if not _SHA256.fullmatch(digest or "") or not isinstance(size, int):
        raise ValueError("invalid CISA Silver manifest Parquet metadata")
    schema = cisa_silver_schema(
        snapshot_kind=snapshot_kind,
        snapshot_id=snapshot_id,
        source_sha256=source_sha256,
        record_count=record_count,
    )
    actual_digest, actual_size = _verify_parquet(
        parquet_path, schema=schema, record_count=record_count
    )
    if actual_digest != digest or actual_size != size:
        raise ValueError("CISA Silver Parquet does not match its manifest")
    return CisaSilverResult(
        DATASET_NAME,
        snapshot_kind,
        snapshot_id,
        source_sha256,
        record_count,
        str(parquet_path),
        str(manifest_path),
        digest,
        size,
        False,
    )
