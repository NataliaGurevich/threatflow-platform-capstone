"""Register committed vulnerability-priority Gold runs in AWS Glue Catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import date
from typing import Any, Literal
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.gold.local_publish import DETAIL_DATASET, PRODUCT_NAME, SUMMARY_DATASET

_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_KEY = re.compile(
    rf"^(?P<prefix>.+)/_commits/{PRODUCT_NAME}/"
    r"snapshot_date=(?P<date>\d{4}-\d{2}-\d{2})/_manifest\.json$"
)
_CLIENT_CONFIG = Config(
    retries={"total_max_attempts": 6, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=60,
    max_pool_connections=20,
)


class GoldCatalogError(RuntimeError):
    """Raised when a committed Gold run cannot be registered safely."""


class GoldCatalogConflict(GoldCatalogError):
    """Raised when a date is already registered to a different immutable run."""


@dataclass(frozen=True)
class CatalogPartitionResult:
    table: str
    snapshot_date: date
    location: str
    status: Literal["PLANNED", "CREATED", "REUSED"]


@dataclass(frozen=True)
class CatalogCommitResult:
    snapshot_date: date
    input_fingerprint: str
    commit_uri: str
    detail: CatalogPartitionResult
    summary: CatalogPartitionResult


@dataclass(frozen=True)
class CatalogSyncResult:
    commits: int
    created_partitions: int
    reused_partitions: int
    planned_partitions: int


class GoldCatalogRegistrar:
    def __init__(
        self,
        *,
        bucket: str,
        prefix: str,
        database: str,
        s3_client: Any,
        glue_client: Any,
        detail_table: str = DETAIL_DATASET,
        summary_table: str = SUMMARY_DATASET,
    ) -> None:
        if not bucket.strip() or not prefix.strip("/") or not database.strip():
            raise ValueError("bucket, prefix, and database must not be empty")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.database = database
        self.s3 = s3_client
        self.glue = glue_client
        self.detail_table = detail_table
        self.summary_table = summary_table

    def register_commit_uri(
        self, commit_uri: str, *, dry_run: bool = False
    ) -> CatalogCommitResult:
        parsed = urlparse(commit_uri)
        if parsed.scheme != "s3" or parsed.netloc != self.bucket:
            raise GoldCatalogError(f"commit URI is outside configured bucket: {commit_uri}")
        return self.register_commit_key(parsed.path.lstrip("/"), dry_run=dry_run)

    def register_commit_key(
        self, commit_key: str, *, dry_run: bool = False
    ) -> CatalogCommitResult:
        match = _COMMIT_KEY.fullmatch(commit_key)
        if match is None or match.group("prefix") != self.prefix:
            raise GoldCatalogError(f"invalid Gold product commit key: {commit_key}")
        snapshot_date = _parse_date(match.group("date"), "commit partition date")
        commit = self._get_json(commit_key, "product commit")
        if commit.get("product") != PRODUCT_NAME or commit.get("status") != "COMMITTED":
            raise GoldCatalogError(f"not a committed {PRODUCT_NAME} product: {commit_key}")
        if commit.get("snapshot_date") != snapshot_date.isoformat():
            raise GoldCatalogError(f"product commit snapshot_date mismatch: {commit_key}")
        fingerprint = commit.get("input_fingerprint")
        if not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None:
            raise GoldCatalogError(f"invalid product commit fingerprint: {commit_key}")

        detail_key = self._validated_dataset_manifest_key(
            commit,
            label="detail",
            dataset=DETAIL_DATASET,
            snapshot_date=snapshot_date,
            fingerprint=fingerprint,
        )
        summary_key = self._validated_dataset_manifest_key(
            commit,
            label="summary",
            dataset=SUMMARY_DATASET,
            snapshot_date=snapshot_date,
            fingerprint=fingerprint,
        )
        detail_table = self._get_catalog_table(self.detail_table)
        summary_table = self._get_catalog_table(self.summary_table)
        # Check both targets before creating either one. Glue has no cross-table
        # transaction, so this prevents a known conflict from leaving one new
        # partition behind while the second table fails.
        self._assert_partition_compatible(
            self.detail_table, snapshot_date, self._run_location(detail_key)
        )
        self._assert_partition_compatible(
            self.summary_table, snapshot_date, self._run_location(summary_key)
        )
        detail = self._register_partition(
            table=self.detail_table,
            snapshot_date=snapshot_date,
            fingerprint=fingerprint,
            manifest_key=detail_key,
            table_data=detail_table,
            dry_run=dry_run,
        )
        summary = self._register_partition(
            table=self.summary_table,
            snapshot_date=snapshot_date,
            fingerprint=fingerprint,
            manifest_key=summary_key,
            table_data=summary_table,
            dry_run=dry_run,
        )
        return CatalogCommitResult(
            snapshot_date=snapshot_date,
            input_fingerprint=fingerprint,
            commit_uri=_s3_uri(self.bucket, commit_key),
            detail=detail,
            summary=summary,
        )

    def sync_history(
        self,
        *,
        start_date: date | None = None,
        end_date: date | None = None,
        dry_run: bool = False,
    ) -> CatalogSyncResult:
        if start_date is not None and end_date is not None and start_date > end_date:
            raise ValueError("start_date must not be after end_date")
        commit_prefix = f"{self.prefix}/_commits/{PRODUCT_NAME}/"
        keys = []
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=commit_prefix):
            for item in page.get("Contents", []):
                key = item.get("Key", "")
                match = _COMMIT_KEY.fullmatch(key)
                if match is None:
                    continue
                item_date = _parse_date(match.group("date"), "commit partition date")
                if start_date is not None and item_date < start_date:
                    continue
                if end_date is not None and item_date > end_date:
                    continue
                keys.append((item_date, key))

        results = [
            self.register_commit_key(key, dry_run=dry_run)
            for _, key in sorted(keys, key=lambda item: (item[0], item[1]))
        ]
        partitions = [
            partition
            for result in results
            for partition in (result.detail, result.summary)
        ]
        return CatalogSyncResult(
            commits=len(results),
            created_partitions=sum(item.status == "CREATED" for item in partitions),
            reused_partitions=sum(item.status == "REUSED" for item in partitions),
            planned_partitions=sum(item.status == "PLANNED" for item in partitions),
        )

    def _validated_dataset_manifest_key(
        self,
        commit: dict[str, Any],
        *,
        label: str,
        dataset: str,
        snapshot_date: date,
        fingerprint: str,
    ) -> str:
        reference = commit.get(label)
        if not isinstance(reference, dict):
            raise GoldCatalogError(f"product commit has no {label} manifest reference")
        relative_key = (
            f"{dataset}/snapshot_date={snapshot_date.isoformat()}/"
            f"run_id={fingerprint}/_manifest.json"
        )
        expected_key = (
            f"{self.prefix}/{relative_key}"
        )
        key = reference.get("key")
        legacy_path = reference.get("path")
        if key == expected_key and legacy_path is None:
            manifest_key = key
        elif legacy_path == relative_key and key is None:
            manifest_key = expected_key
        else:
            raise GoldCatalogError(f"product commit {label} manifest key is invalid")
        expected_sha256 = reference.get("sha256")
        if not isinstance(expected_sha256, str) or _FINGERPRINT.fullmatch(expected_sha256) is None:
            raise GoldCatalogError(f"product commit {label} manifest checksum is invalid")
        manifest, encoded = self._get_json_bytes(manifest_key, f"{label} manifest")
        if hashlib.sha256(encoded).hexdigest() != expected_sha256:
            raise GoldCatalogError(f"product commit {label} manifest checksum mismatch")
        if (
            manifest.get("dataset") != dataset
            or manifest.get("snapshot_date") != snapshot_date.isoformat()
            or manifest.get("input_fingerprint") != fingerprint
        ):
            raise GoldCatalogError(f"product commit {label} manifest identity mismatch")
        return manifest_key

    def _register_partition(
        self,
        *,
        table: str,
        snapshot_date: date,
        fingerprint: str,
        manifest_key: str,
        table_data: dict[str, Any],
        dry_run: bool,
    ) -> CatalogPartitionResult:
        location = self._run_location(manifest_key)
        existing = self._get_partition(table, snapshot_date)
        if existing is not None:
            existing_location = existing.get("StorageDescriptor", {}).get("Location")
            if _normalized_location(existing_location) != _normalized_location(location):
                raise GoldCatalogConflict(
                    f"{self.database}.{table} partition {snapshot_date} points to "
                    f"{existing_location}, expected {location}"
                )
            return CatalogPartitionResult(table, snapshot_date, location, "REUSED")
        if dry_run:
            return CatalogPartitionResult(table, snapshot_date, location, "PLANNED")

        partition_input = {
            "Values": [snapshot_date.isoformat()],
            "StorageDescriptor": _partition_storage_descriptor(
                table_data["StorageDescriptor"], location
            ),
            "Parameters": {
                "input_fingerprint": fingerprint,
                "run_id": fingerprint,
                "product": PRODUCT_NAME,
                "status": "COMMITTED",
            },
        }
        try:
            self.glue.create_partition(
                DatabaseName=self.database,
                TableName=table,
                PartitionInput=partition_input,
            )
        except self.glue.exceptions.AlreadyExistsException:
            raced = self._get_partition(table, snapshot_date)
            raced_location = (raced or {}).get("StorageDescriptor", {}).get("Location")
            if _normalized_location(raced_location) != _normalized_location(location):
                raise GoldCatalogConflict(
                    f"{self.database}.{table} partition {snapshot_date} was concurrently "
                    f"registered to {raced_location}, expected {location}"
                ) from None
            return CatalogPartitionResult(table, snapshot_date, location, "REUSED")
        return CatalogPartitionResult(table, snapshot_date, location, "CREATED")

    def _get_catalog_table(self, table: str) -> dict[str, Any]:
        table_data = self.glue.get_table(DatabaseName=self.database, Name=table)["Table"]
        _validate_catalog_table(table_data, table)
        return table_data

    def _run_location(self, manifest_key: str) -> str:
        return _s3_uri(self.bucket, manifest_key.rsplit("/", 1)[0] + "/")

    def _assert_partition_compatible(
        self, table: str, snapshot_date: date, expected_location: str
    ) -> None:
        existing = self._get_partition(table, snapshot_date)
        if existing is None:
            return
        existing_location = existing.get("StorageDescriptor", {}).get("Location")
        if _normalized_location(existing_location) != _normalized_location(
            expected_location
        ):
            raise GoldCatalogConflict(
                f"{self.database}.{table} partition {snapshot_date} points to "
                f"{existing_location}, expected {expected_location}"
            )

    def _get_partition(self, table: str, snapshot_date: date) -> dict[str, Any] | None:
        try:
            return self.glue.get_partition(
                DatabaseName=self.database,
                TableName=table,
                PartitionValues=[snapshot_date.isoformat()],
            )["Partition"]
        except self.glue.exceptions.EntityNotFoundException:
            return None

    def _get_json(self, key: str, label: str) -> dict[str, Any]:
        value, _ = self._get_json_bytes(key, label)
        return value

    def _get_json_bytes(self, key: str, label: str) -> tuple[dict[str, Any], bytes]:
        response = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"]
        try:
            encoded = body.read()
        finally:
            body.close()
        try:
            value = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GoldCatalogError(f"invalid {label}: {_s3_uri(self.bucket, key)}") from exc
        if not isinstance(value, dict):
            raise GoldCatalogError(f"invalid {label}: {_s3_uri(self.bucket, key)}")
        return value, encoded


def _validate_catalog_table(table: dict[str, Any], expected_name: str) -> None:
    if table.get("Name") != expected_name or table.get("TableType") != "EXTERNAL_TABLE":
        raise GoldCatalogError(f"invalid Glue Catalog table: {expected_name}")
    partition_keys = table.get("PartitionKeys")
    if (
        not isinstance(partition_keys, list)
        or len(partition_keys) != 1
        or not isinstance(partition_keys[0], dict)
        or partition_keys[0].get("Name") != "snapshot_date"
        or partition_keys[0].get("Type") != "date"
    ):
        raise GoldCatalogError(f"invalid partition keys for Glue Catalog table: {expected_name}")
    descriptor = table.get("StorageDescriptor")
    if not isinstance(descriptor, dict) or not descriptor.get("Columns"):
        raise GoldCatalogError(f"Glue Catalog table has no storage columns: {expected_name}")


def _partition_storage_descriptor(descriptor: dict[str, Any], location: str) -> dict[str, Any]:
    result = {
        key: descriptor[key]
        for key in (
            "Columns",
            "InputFormat",
            "OutputFormat",
            "Compressed",
            "NumberOfBuckets",
            "SerdeInfo",
            "BucketColumns",
            "SortColumns",
            "Parameters",
            "StoredAsSubDirectories",
        )
        if key in descriptor
    }
    result["Location"] = location
    return result


def _parse_date(value: str, label: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise GoldCatalogError(f"invalid {label}: {value}") from exc


def _normalized_location(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("s3://"):
        return ""
    return value.rstrip("/") + "/"


def _s3_uri(bucket: str, key: str) -> str:
    return f"s3://{bucket}/{key}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Register committed vulnerability-priority Gold partitions in Glue Catalog."
    )
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", default="gold")
    parser.add_argument("--database", required=True)
    parser.add_argument("--region", default=None)
    parser.add_argument("--start-date", type=date.fromisoformat)
    parser.add_argument("--end-date", type=date.fromisoformat)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    session = boto3.Session(region_name=args.region)
    registrar = GoldCatalogRegistrar(
        bucket=args.bucket,
        prefix=args.prefix,
        database=args.database,
        s3_client=session.client("s3", config=_CLIENT_CONFIG),
        glue_client=session.client("glue", config=_CLIENT_CONFIG),
    )
    try:
        result = registrar.sync_history(
            start_date=args.start_date,
            end_date=args.end_date,
            dry_run=args.dry_run,
        )
    except (GoldCatalogError, ClientError, ValueError) as exc:
        print(f"Gold Catalog sync failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
