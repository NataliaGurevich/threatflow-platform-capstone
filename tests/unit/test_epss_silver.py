import gzip
import json
from datetime import UTC, date, datetime

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation import epss_silver

SCORE_DATE = date(2026, 11, 11)
ACQUIRED_AT = datetime(2026, 11, 12, 6, 0, tzinfo=UTC)


def raw(*, first_score: str = "0.1") -> bytes:
    return gzip.compress(
        (
            "#model_version:v2025.03.14,score_date:2026-11-11T00:00:00Z\n"
            "cve,epss,percentile\n"
            f"CVE-2026-0001,{first_score},0.2\n"
            "CVE-2026-0002,0.3,0.4\n"
        ).encode()
    )


def transform(content: bytes, output_root, *, expected_count: int = 2):
    return epss_silver.transform_epss_bytes(
        content,
        score_date=SCORE_DATE,
        source_sha256=calculate_sha256(content),
        source_uri=f"s3://bronze/{calculate_sha256(content)}.csv.gz",
        acquired_at=ACQUIRED_AT,
        expected_record_count=expected_count,
        output_root=output_root,
    )


def test_transform_writes_typed_partition_manifest_and_reuses(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    content = raw()

    created = transform(content, tmp_path)
    reused = transform(content, tmp_path)

    assert created.created is True
    assert reused.created is False
    assert reused.parquet_sha256 == created.parquet_sha256
    assert created.record_count == 2
    table = pq.read_table(created.parquet_path)
    assert table.schema.names == [
        "cve_id",
        "score_date",
        "epss_score",
        "percentile",
        "source_sha256",
    ]
    assert table.schema.field("score_date").type == pa.date32()
    assert table.schema.field("epss_score").type == pa.float64()
    assert table.column("source_sha256").to_pylist() == [
        calculate_sha256(content),
        calculate_sha256(content),
    ]
    manifest = json.loads(open(created.manifest_path).read())
    assert manifest["schema_version"] == 1
    assert manifest["transform_version"] == "1.0.0"
    assert manifest["record_count"] == 2
    assert manifest["parquet"]["compression"] == "zstd"


def test_manifest_count_mismatch_fails_before_publish(tmp_path) -> None:
    with pytest.raises(ValueError, match="manifest count mismatch"):
        transform(raw(), tmp_path, expected_count=3)

    assert list(tmp_path.rglob("*.parquet")) == []
    assert list(tmp_path.rglob("_manifest.json")) == []


def test_completeness_failure_does_not_publish(tmp_path) -> None:
    with pytest.raises(ValueError, match="dataset incomplete"):
        transform(raw(), tmp_path)

    assert list(tmp_path.rglob("*.parquet")) == []
    assert list(tmp_path.rglob("_manifest.json")) == []


def test_conflicting_source_for_same_score_date_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    transform(raw(), tmp_path)

    with pytest.raises(FileExistsError, match="conflicting EPSS Silver partition"):
        transform(raw(first_score="0.9"), tmp_path)
