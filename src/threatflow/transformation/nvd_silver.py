"""Build one immutable NVD Silver window from a committed Bronze page set."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from threatflow.ingestion.nvd_parser import parse_response
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.nvd_window import (
    NvdWindowManifest,
    NvdWindowPage,
    parse_nvd_window_manifest,
)

DATASET_NAME = "nvd_cve_windows"
SCHEMA_VERSION = 1
TRANSFORM_VERSION = "1.0.0"
PARQUET_FILE_NAME = "nvd_cves.parquet"
MANIFEST_FILE_NAME = "_manifest.json"
PARQUET_COMPRESSION = "zstd"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NvdSilverPageInput:
    lineage: NvdWindowPage
    content: bytes


@dataclass(frozen=True)
class NvdSilverResult:
    dataset: str
    mode: str
    window_id: str
    window_start: datetime
    window_end: datetime
    record_count: int
    parquet_path: str
    manifest_path: str
    parquet_sha256: str
    parquet_size_bytes: int
    created: bool


def transform_nvd_window(
    window_content: bytes,
    *,
    window_sha256: str,
    window_uri: str,
    window_version_id: str | None,
    pages: list[NvdSilverPageInput],
    output_root: str | Path,
) -> NvdSilverResult:
    """Validate a complete exact-version NVD window and commit one Silver partition."""
    if not _SHA256.fullmatch(window_sha256) or calculate_sha256(window_content) != window_sha256:
        raise ValueError("NVD Bronze window manifest SHA-256 mismatch")
    if not window_uri:
        raise ValueError("NVD Bronze window requires URI lineage")
    window = parse_nvd_window_manifest(window_content)
    if len(pages) != len(window.pages):
        raise ValueError("NVD Bronze page set is incomplete")

    by_identity = {_page_identity(item.lineage): item for item in pages}
    selected: dict[str, tuple[dict[str, Any], NvdWindowPage]] = {}
    parsed_total = 0
    for expected in window.pages:
        item = by_identity.get(_page_identity(expected))
        if item is None or item.lineage != expected:
            raise ValueError("NVD Bronze page exact lineage does not match window manifest")
        if len(item.content) != expected.size_bytes:
            raise ValueError("NVD Bronze page size does not match window manifest")
        if calculate_sha256(item.content) != expected.sha256:
            raise ValueError("NVD Bronze page SHA-256 does not match window manifest")
        metadata, records = parse_response(item.content)
        if (
            metadata["startIndex"] != expected.start_index
            or metadata["resultsPerPage"] != expected.record_count
            or metadata["totalResults"] != window.total_results
            or len(records) != expected.record_count
        ):
            raise ValueError("NVD Bronze page pagination does not match window manifest")
        parsed_total += len(records)
        for record in records:
            prior = selected.get(record["cve_id"])
            if prior is None or record["last_modified"] > prior[0]["last_modified"]:
                selected[record["cve_id"]] = (record, expected)
            elif record["last_modified"] == prior[0]["last_modified"] and record != prior[0]:
                raise ValueError(
                    f"conflicting duplicate CVE {record['cve_id']} with equal lastModified"
                )
    if parsed_total != window.total_results:
        raise ValueError("NVD parsed page count does not match window totalResults")

    partition = (
        Path(output_root)
        / DATASET_NAME
        / f"mode={window.mode}"
        / f"window_end={_path_timestamp(window.requested_end)}"
        / f"window_id={window_sha256}"
    )
    parquet_path = partition / PARQUET_FILE_NAME
    manifest_path = partition / MANIFEST_FILE_NAME
    rows = [
        _silver_row(record, page, window, window_sha256)
        for record, page in (selected[key] for key in sorted(selected))
    ]
    schema = nvd_silver_schema(window, window_sha256, len(rows))
    if manifest_path.exists():
        return _reuse(parquet_path, manifest_path, window, window_sha256, len(rows))

    partition.mkdir(parents=True, exist_ok=True)
    if not parquet_path.exists():
        _write_parquet(parquet_path, pa.Table.from_pylist(rows, schema=schema))
    parquet_sha256, parquet_size = _verify_parquet(
        parquet_path, schema=schema, record_count=len(rows)
    )
    payload = {
        "dataset": DATASET_NAME,
        "schema_version": SCHEMA_VERSION,
        "transform_version": TRANSFORM_VERSION,
        "mode": window.mode,
        "window_id": window_sha256,
        "window_start": window.requested_start.astimezone(UTC).isoformat(),
        "window_end": window.requested_end.astimezone(UTC).isoformat(),
        "source_record_count": window.total_results,
        "record_count": len(rows),
        "source": {
            "name": "nvd",
            "uri": window_uri,
            "sha256": window_sha256,
            "acquired_at": window.acquired_at.astimezone(UTC).isoformat(),
            "pages": [asdict(page) for page in window.pages],
        },
        "parquet": {
            "file": PARQUET_FILE_NAME,
            "sha256": parquet_sha256,
            "size_bytes": parquet_size,
            "compression": PARQUET_COMPRESSION,
        },
        "committed_at": datetime.now(UTC).isoformat(),
    }
    if window_version_id is not None:
        payload["source"]["version_id"] = window_version_id
    _publish_manifest(manifest_path, payload)
    return NvdSilverResult(
        DATASET_NAME,
        window.mode,
        window_sha256,
        window.requested_start,
        window.requested_end,
        len(rows),
        str(parquet_path),
        str(manifest_path),
        parquet_sha256,
        parquet_size,
        True,
    )


def nvd_silver_schema(
    window: NvdWindowManifest, window_sha256: str, record_count: int
) -> pa.Schema:
    metadata = {
        b"threatflow.dataset": DATASET_NAME.encode(),
        b"threatflow.schema_version": str(SCHEMA_VERSION).encode(),
        b"threatflow.transform_version": TRANSFORM_VERSION.encode(),
        b"threatflow.mode": window.mode.encode(),
        b"threatflow.window_sha256": window_sha256.encode(),
        b"threatflow.record_count": str(record_count).encode(),
    }
    return pa.schema(
        [
            pa.field("cve_id", pa.string(), nullable=False),
            pa.field("description", pa.string(), nullable=False),
            pa.field("published", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("last_modified", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("cvss_version", pa.string()),
            pa.field("cvss_score", pa.float64()),
            pa.field("cvss_severity", pa.string()),
            pa.field("cvss_vector", pa.string()),
            pa.field("cwe_ids", pa.list_(pa.string())),
            pa.field("references_json", pa.string()),
            pa.field("request_mode", pa.string(), nullable=False),
            pa.field("window_start", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("window_end", pa.timestamp("us", tz="UTC"), nullable=False),
            pa.field("window_sha256", pa.string(), nullable=False),
            pa.field("bronze_page_sha256", pa.string(), nullable=False),
            pa.field("bronze_page_backend", pa.string(), nullable=False),
            pa.field("bronze_page_uri", pa.string(), nullable=False),
            pa.field("bronze_page_version_id", pa.string()),
        ],
        metadata=metadata,
    )


def verify_committed_nvd_partition(
    *,
    output_root: str | Path,
    window_content: bytes,
    window_sha256: str,
) -> NvdSilverResult | None:
    """Verify a committed local NVD window partition, or return None when absent."""
    window = parse_nvd_window_manifest(window_content)
    partition = (
        Path(output_root)
        / DATASET_NAME
        / f"mode={window.mode}"
        / f"window_end={_path_timestamp(window.requested_end)}"
        / f"window_id={window_sha256}"
    )
    manifest_path = partition / MANIFEST_FILE_NAME
    if not manifest_path.exists():
        return None
    payload = json.loads(manifest_path.read_text())
    record_count = payload.get("record_count")
    if type(record_count) is not int or record_count < 0:
        raise ValueError("NVD Silver manifest record_count is invalid")
    return _reuse(
        partition / PARQUET_FILE_NAME,
        manifest_path,
        window,
        window_sha256,
        record_count,
    )


def _silver_row(
    record: dict[str, Any],
    page: NvdWindowPage,
    window: NvdWindowManifest,
    window_sha256: str,
) -> dict[str, Any]:
    return {
        **{key: record[key] for key in record if key != "references"},
        "references_json": (
            json.dumps(record["references"], sort_keys=True, separators=(",", ":"))
            if record["references"] is not None
            else None
        ),
        "request_mode": window.mode,
        "window_start": window.requested_start.astimezone(UTC),
        "window_end": window.requested_end.astimezone(UTC),
        "window_sha256": window_sha256,
        "bronze_page_sha256": page.sha256,
        "bronze_page_backend": page.backend,
        "bronze_page_uri": page.uri or f"s3://{page.bucket}/{page.key}",
        "bronze_page_version_id": page.version_id,
    }


def _write_parquet(path: Path, table: pa.Table) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".nvd-", delete=False) as stream:
            temporary = Path(stream.name)
        pq.write_table(
            table,
            temporary,
            compression=PARQUET_COMPRESSION,
            compression_level=3,
            use_dictionary=True,
            write_statistics=True,
            version="2.6",
            write_page_checksum=True,
        )
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _verify_parquet(path: Path, *, schema: pa.Schema, record_count: int) -> tuple[str, int]:
    if not path.is_file():
        raise FileNotFoundError(f"NVD Silver Parquet is missing: {path}")
    table = pq.read_table(path)
    if table.schema != schema or table.num_rows != record_count:
        raise ValueError("NVD Silver Parquet failed schema or row-count verification")
    return calculate_sha256(path.read_bytes()), path.stat().st_size


def _reuse(
    parquet_path: Path,
    manifest_path: Path,
    window: NvdWindowManifest,
    window_sha256: str,
    record_count: int,
) -> NvdSilverResult:
    payload = json.loads(manifest_path.read_text())
    identity = (
        payload.get("dataset"),
        payload.get("mode"),
        payload.get("window_id"),
        payload.get("record_count"),
        payload.get("source", {}).get("sha256"),
    )
    expected = (DATASET_NAME, window.mode, window_sha256, record_count, window_sha256)
    if identity != expected:
        raise FileExistsError("conflicting NVD Silver commit manifest")
    parquet = payload.get("parquet", {})
    sha256, size = _verify_parquet(
        parquet_path,
        schema=nvd_silver_schema(window, window_sha256, record_count),
        record_count=record_count,
    )
    if (parquet.get("sha256"), parquet.get("size_bytes")) != (sha256, size):
        raise ValueError("NVD Silver manifest does not match Parquet")
    return NvdSilverResult(
        DATASET_NAME,
        window.mode,
        window_sha256,
        window.requested_start,
        window.requested_end,
        record_count,
        str(parquet_path),
        str(manifest_path),
        sha256,
        size,
        False,
    )


def _publish_manifest(path: Path, payload: dict[str, Any]) -> None:
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode()
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".manifest-", delete=False) as f:
            temporary = Path(f.name)
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise FileExistsError(
                f"conflicting NVD Silver manifest already exists: {path}"
            ) from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _path_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H-%M-%SZ")


def _page_identity(page: NvdWindowPage) -> tuple[str, str, str | None]:
    return (page.backend, page.uri or page.key or "", page.version_id)
