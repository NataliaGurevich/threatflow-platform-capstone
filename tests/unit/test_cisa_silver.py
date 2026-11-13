import json
from datetime import UTC, datetime
from pathlib import Path

import pyarrow.parquet as pq
import pytest

from threatflow.ingestion.cisa_parser import parse_catalog, parse_catalog_document
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.cisa_silver import transform_cisa_bytes

ACQUIRED_AT = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)
RECORD = {
    "cveID": "CVE-2026-1234",
    "vendorProject": "Vendor",
    "product": "Product",
    "vulnerabilityName": "Issue",
    "dateAdded": "2026-11-01",
    "shortDescription": "Description",
    "requiredAction": "Patch",
    "dueDate": "2026-11-20",
    "knownRansomwareCampaignUse": "Unknown",
    "notes": "https://example.test",
    "cwes": ["CWE-79"],
}


def catalog_bytes(**changes):
    value = {
        "catalogVersion": "2026.11.13",
        "dateReleased": "2026-11-13T09:00:00Z",
        "count": 1,
        "vulnerabilities": [RECORD],
    }
    value.update(changes)
    return json.dumps(value).encode()


def transform(content, tmp_path, **changes):
    return transform_cisa_bytes(
        content,
        snapshot_kind="snapshot",
        source_sha256=calculate_sha256(content),
        source_uri="s3://bronze/bronze/source=cisa_kev/object.json",
        source_version_id="version-1",
        acquired_at=ACQUIRED_AT,
        output_root=tmp_path,
        **changes,
    )


def test_document_parser_preserves_metadata_without_changing_database_projection():
    parsed = parse_catalog_document(catalog_bytes())
    assert parsed.catalog_version == "2026.11.13"
    assert parsed.date_released == datetime(2026, 11, 13, 9, 0, tzinfo=UTC)
    assert parsed.records[0]["cwes"] == ("CWE-79",)
    assert "cwes" not in parse_catalog(catalog_bytes())[0]


def test_document_parser_rejects_duplicate_cves():
    with pytest.raises(ValueError, match="duplicate"):
        parse_catalog_document(catalog_bytes(count=2, vulnerabilities=[RECORD, RECORD]))


def test_transform_writes_typed_parquet_manifest_and_reuses_commit(tmp_path):
    content = catalog_bytes()
    first = transform(content, tmp_path)
    assert first.created is True
    table = pq.read_table(first.parquet_path)
    assert table.num_rows == 1
    assert table.column("cve_id").to_pylist() == ["CVE-2026-1234"]
    assert table.column("cwes").to_pylist() == [["CWE-79"]]
    assert table.schema.field("date_added").type.__str__() == "date32[day]"
    assert table.schema.metadata[b"threatflow.snapshot_id"].decode() == first.source_sha256

    manifest = json.loads(Path(first.manifest_path).read_text())
    assert manifest["snapshot"]["catalog_version"] == "2026.11.13"
    assert manifest["source"]["version_id"] == "version-1"
    assert manifest["parquet"]["compression"] == "zstd"

    second = transform(content, tmp_path)
    assert second.created is False
    assert second.parquet_sha256 == first.parquet_sha256


def test_git_history_uses_revision_as_partition_identity(tmp_path):
    content = catalog_bytes()
    revision = "a" * 40
    result = transform_cisa_bytes(
        content,
        snapshot_kind="git_history",
        source_revision=revision,
        source_sha256=calculate_sha256(content),
        source_uri="s3://bronze/history.json",
        acquired_at=ACQUIRED_AT,
        output_root=tmp_path,
    )
    assert result.snapshot_id == revision
    assert f"snapshot_id={revision}" in result.parquet_path


def test_existing_parquet_without_manifest_is_recovered(tmp_path):
    content = catalog_bytes()
    first = transform(content, tmp_path)
    manifest_path = first.manifest_path
    Path(manifest_path).unlink()
    recovered = transform(content, tmp_path)
    assert recovered.created is True
    assert recovered.parquet_sha256 == first.parquet_sha256


def test_conflicting_committed_partition_fails(tmp_path):
    content = catalog_bytes()
    result = transform(content, tmp_path)
    manifest = json.loads(Path(result.manifest_path).read_text())
    manifest["source"]["sha256"] = "0" * 64
    Path(result.manifest_path).write_text(json.dumps(manifest))
    with pytest.raises(FileExistsError, match="conflicting"):
        transform(content, tmp_path)


def test_invalid_lineage_and_expected_count_fail_before_commit(tmp_path):
    content = catalog_bytes()
    with pytest.raises(ValueError, match="manifest count"):
        transform(content, tmp_path, expected_record_count=2)
    with pytest.raises(ValueError, match="snapshot_kind"):
        transform_cisa_bytes(
            content,
            snapshot_kind="git_history_invalid",  # type: ignore[arg-type]
            source_sha256=calculate_sha256(content),
            source_uri="local://invalid",
            acquired_at=ACQUIRED_AT,
            output_root=tmp_path,
        )
