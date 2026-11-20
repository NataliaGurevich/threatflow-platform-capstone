import hashlib
import io
import json
from datetime import date

import pytest

from threatflow.gold.catalog import (
    GoldCatalogConflict,
    GoldCatalogError,
    GoldCatalogRegistrar,
)


class Body(io.BytesIO):
    pass


class Paginator:
    def __init__(self, objects):
        self.objects = objects

    def paginate(self, *, Bucket, Prefix):
        del Bucket
        yield {
            "Contents": [
                {"Key": key} for key in sorted(self.objects) if key.startswith(Prefix)
            ]
        }


class FakeS3:
    def __init__(self, objects):
        self.objects = objects

    def get_object(self, *, Bucket, Key):
        del Bucket
        return {"Body": Body(self.objects[Key])}

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return Paginator(self.objects)


class EntityNotFoundException(Exception):
    pass


class AlreadyExistsException(Exception):
    pass


class Exceptions:
    EntityNotFoundException = EntityNotFoundException
    AlreadyExistsException = AlreadyExistsException


class FakeGlue:
    exceptions = Exceptions

    def __init__(self):
        self.partitions = {}
        self.create_calls = []

    def get_table(self, *, DatabaseName, Name):
        assert DatabaseName == "threatflow_gold"
        return {
            "Table": {
                "Name": Name,
                "TableType": "EXTERNAL_TABLE",
                "PartitionKeys": [{"Name": "snapshot_date", "Type": "date"}],
                "StorageDescriptor": {
                    "Columns": [{"Name": "cve_id", "Type": "string"}],
                    "InputFormat": "parquet-input",
                    "OutputFormat": "parquet-output",
                    "SerdeInfo": {"SerializationLibrary": "parquet-serde"},
                    "Parameters": {"classification": "parquet"},
                },
            }
        }

    def get_partition(self, *, DatabaseName, TableName, PartitionValues):
        key = (DatabaseName, TableName, tuple(PartitionValues))
        if key not in self.partitions:
            raise EntityNotFoundException
        return {"Partition": self.partitions[key]}

    def create_partition(self, *, DatabaseName, TableName, PartitionInput):
        key = (DatabaseName, TableName, tuple(PartitionInput["Values"]))
        if key in self.partitions:
            raise AlreadyExistsException
        self.partitions[key] = PartitionInput
        self.create_calls.append((TableName, PartitionInput))


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def committed_objects(
    snapshot_date="2026-11-18", fingerprint="a" * 64, *, legacy_paths=False
):
    objects = {}
    references = {}
    for label, dataset in (
        ("detail", "vulnerability_priority_daily"),
        ("summary", "vulnerability_priority_summary_daily"),
    ):
        key = (
            f"gold/{dataset}/snapshot_date={snapshot_date}/"
            f"run_id={fingerprint}/_manifest.json"
        )
        encoded = _json_bytes(
            {
                "dataset": dataset,
                "snapshot_date": snapshot_date,
                "input_fingerprint": fingerprint,
            }
        )
        objects[key] = encoded
        reference_name = "path" if legacy_paths else "key"
        reference_value = key.removeprefix("gold/") if legacy_paths else key
        references[label] = {
            reference_name: reference_value,
            "sha256": hashlib.sha256(encoded).hexdigest(),
        }
    commit_key = (
        "gold/_commits/vulnerability_priority/"
        f"snapshot_date={snapshot_date}/_manifest.json"
    )
    objects[commit_key] = _json_bytes(
        {
            "product": "vulnerability_priority",
            "status": "COMMITTED",
            "snapshot_date": snapshot_date,
            "input_fingerprint": fingerprint,
            **references,
        }
    )
    return objects, commit_key


def registrar(objects, glue=None):
    glue = glue or FakeGlue()
    return (
        GoldCatalogRegistrar(
            bucket="gold-bucket",
            prefix="gold",
            database="threatflow_gold",
            s3_client=FakeS3(objects),
            glue_client=glue,
        ),
        glue,
    )


def test_registers_both_partitions_and_reuses_identical_locations() -> None:
    objects, commit_key = committed_objects()
    catalog, glue = registrar(objects)

    created = catalog.register_commit_key(commit_key)
    reused = catalog.register_commit_key(commit_key)

    assert created.detail.status == "CREATED"
    assert created.summary.status == "CREATED"
    assert reused.detail.status == "REUSED"
    assert reused.summary.status == "REUSED"
    assert len(glue.create_calls) == 2
    assert created.detail.location.endswith(
        "/snapshot_date=2026-11-18/run_id=" + "a" * 64 + "/"
    )


def test_registers_legacy_relative_manifest_paths() -> None:
    objects, commit_key = committed_objects(legacy_paths=True)
    catalog, glue = registrar(objects)

    result = catalog.register_commit_key(commit_key, dry_run=True)

    assert result.detail.status == "PLANNED"
    assert result.detail.location.startswith(
        "s3://gold-bucket/gold/vulnerability_priority_daily/"
    )
    assert glue.create_calls == []
    assert all(
        item["Parameters"]["status"] == "COMMITTED"
        and item["Parameters"]["run_id"] == "a" * 64
        for _, item in glue.create_calls
    )


def test_existing_partition_with_other_run_is_conflict() -> None:
    objects, commit_key = committed_objects()
    catalog, glue = registrar(objects)
    glue.partitions[
        ("threatflow_gold", "vulnerability_priority_daily", ("2026-11-18",))
    ] = {
        "StorageDescriptor": {
            "Location": "s3://gold-bucket/gold/vulnerability_priority_daily/"
            "snapshot_date=2026-11-18/run_id="
            + "b" * 64
            + "/"
        }
    }

    with pytest.raises(GoldCatalogConflict, match="points to"):
        catalog.register_commit_key(commit_key)

    assert glue.create_calls == []


def test_summary_conflict_is_detected_before_detail_is_created() -> None:
    objects, commit_key = committed_objects()
    catalog, glue = registrar(objects)
    glue.partitions[
        (
            "threatflow_gold",
            "vulnerability_priority_summary_daily",
            ("2026-11-18",),
        )
    ] = {
        "StorageDescriptor": {
            "Location": "s3://gold-bucket/gold/vulnerability_priority_summary_daily/"
            "snapshot_date=2026-11-18/run_id="
            + "b" * 64
            + "/"
        }
    }

    with pytest.raises(GoldCatalogConflict, match="summary_daily"):
        catalog.register_commit_key(commit_key)

    assert glue.create_calls == []


def test_rejects_uncommitted_product_and_manifest_checksum_mismatch() -> None:
    objects, commit_key = committed_objects()
    commit = json.loads(objects[commit_key])
    commit["status"] = "WRITING"
    objects[commit_key] = _json_bytes(commit)
    catalog, _ = registrar(objects)
    with pytest.raises(GoldCatalogError, match="not a committed"):
        catalog.register_commit_key(commit_key)

    objects, commit_key = committed_objects()
    commit = json.loads(objects[commit_key])
    commit["detail"]["sha256"] = "b" * 64
    objects[commit_key] = _json_bytes(commit)
    catalog, _ = registrar(objects)
    with pytest.raises(GoldCatalogError, match="checksum mismatch"):
        catalog.register_commit_key(commit_key)


def test_history_sync_filters_dates_and_supports_dry_run() -> None:
    first, _ = committed_objects("2026-11-17", "a" * 64)
    second, _ = committed_objects("2026-11-18", "b" * 64)
    catalog, glue = registrar({**first, **second})

    result = catalog.sync_history(
        start_date=date(2026, 11, 18),
        end_date=date(2026, 11, 18),
        dry_run=True,
    )

    assert result.commits == 1
    assert result.planned_partitions == 2
    assert result.created_partitions == 0
    assert glue.create_calls == []
