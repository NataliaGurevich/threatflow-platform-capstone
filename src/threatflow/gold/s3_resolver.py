"""Resolve a deterministic Gold input plan from committed S3 Silver manifests."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EPSS_MANIFEST = re.compile(
    r"^epss_scores/score_date=(\d{4}-\d{2}-\d{2})/_manifest\.json$"
)


class S3GoldInputError(ValueError):
    """Raised when S3 Silver cannot provide a valid input snapshot."""


@dataclass(frozen=True)
class S3SilverArtifact:
    bucket: str
    manifest_key: str
    parquet_key: str
    manifest: dict[str, Any]

    @property
    def parquet_uri(self) -> str:
        return f"s3://{self.bucket}/{self.parquet_key}"

    def reference(self) -> dict[str, Any]:
        parquet = self.manifest["parquet"]
        return {
            "manifest": f"s3://{self.bucket}/{self.manifest_key}",
            "parquet": self.parquet_uri,
            "sha256": parquet["sha256"],
            "size_bytes": parquet["size_bytes"],
            "record_count": self.manifest["record_count"],
            "schema_version": self.manifest["schema_version"],
            "transform_version": self.manifest["transform_version"],
        }


@dataclass(frozen=True)
class S3GoldInputPlan:
    snapshot_date: date
    source_cutoff: datetime
    nvd: tuple[S3SilverArtifact, ...]
    cisa: S3SilverArtifact
    epss_current: S3SilverArtifact
    epss_previous: S3SilverArtifact
    nvd_history_complete: bool

    def fingerprint_plan(self) -> dict[str, Any]:
        return {
            "nvd": {
                "history_complete": self.nvd_history_complete,
                "artifacts": [item.reference() for item in self.nvd],
            },
            "cisa": self.cisa.reference(),
            "epss_current": self.epss_current.reference(),
            "epss_previous": self.epss_previous.reference(),
        }


class S3SilverResolver:
    def __init__(self, bucket: str, prefix: str = "silver", *, s3_client: Any) -> None:
        if not bucket.strip() or not prefix.strip("/"):
            raise ValueError("Silver bucket and prefix must not be empty")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.s3 = s3_client

    def select_latest_ready_snapshot_date(
        self,
        *,
        latest_allowed_date: date,
        max_input_lag_days: int,
    ) -> date:
        """Select the newest committed EPSS date with its seven-day comparison input."""
        if type(latest_allowed_date) is not date:
            raise TypeError("latest_allowed_date must be a date")
        if type(max_input_lag_days) is not int or max_input_lag_days < 0:
            raise ValueError("max_input_lag_days must be a non-negative integer")

        prefix = f"{self.prefix}/epss_scores/"
        committed_dates = set()
        for key in self._manifest_keys(prefix):
            relative_key = key.removeprefix(f"{self.prefix}/")
            match = _EPSS_MANIFEST.fullmatch(relative_key)
            if match is None:
                continue
            try:
                committed_dates.add(date.fromisoformat(match.group(1)))
            except ValueError as exc:
                raise S3GoldInputError(f"invalid EPSS partition date: {key}") from exc

        candidates = [
            item
            for item in committed_dates
            if item <= latest_allowed_date and item - timedelta(days=7) in committed_dates
        ]
        if not candidates:
            raise S3GoldInputError(
                "no ready EPSS snapshot has both current and seven-day comparison manifests"
            )
        selected = max(candidates)
        lag_days = (latest_allowed_date - selected).days
        if lag_days > max_input_lag_days:
            raise S3GoldInputError(
                f"latest ready EPSS snapshot {selected} is {lag_days} days behind "
                f"the allowed date {latest_allowed_date}; maximum is {max_input_lag_days}"
            )
        return selected

    def resolve(
        self,
        snapshot_date: date,
        *,
        source_cutoff: datetime,
        snapshot_type: str,
        nvd_history_complete: bool,
    ) -> S3GoldInputPlan:
        if source_cutoff.tzinfo is None or source_cutoff.utcoffset() is None:
            raise ValueError("source_cutoff must be timezone-aware")
        if snapshot_type not in {"OBSERVED", "RECONSTRUCTED"}:
            raise ValueError("snapshot_type must be OBSERVED or RECONSTRUCTED")
        current = self._load_partition_manifest(
            f"epss_scores/score_date={snapshot_date.isoformat()}", "epss_scores"
        )
        previous_date = snapshot_date - timedelta(days=7)
        previous = self._load_partition_manifest(
            f"epss_scores/score_date={previous_date.isoformat()}", "epss_scores"
        )
        if current.manifest.get("score_date") != snapshot_date.isoformat():
            raise S3GoldInputError("current EPSS manifest score_date mismatch")
        if previous.manifest.get("score_date") != previous_date.isoformat():
            raise S3GoldInputError("previous EPSS manifest score_date mismatch")

        cisa_kind = "snapshot" if snapshot_type == "OBSERVED" else "git_history"
        cisa = self._select_cisa(cisa_kind, source_cutoff)
        nvd = self._select_nvd(source_cutoff)
        return S3GoldInputPlan(
            snapshot_date=snapshot_date,
            source_cutoff=source_cutoff,
            nvd=nvd,
            cisa=cisa,
            epss_current=current,
            epss_previous=previous,
            nvd_history_complete=nvd_history_complete,
        )

    def _select_cisa(self, kind: str, cutoff: datetime) -> S3SilverArtifact:
        prefix = f"{self.prefix}/cisa_kev_snapshots/snapshot_kind={kind}/"
        candidates = []
        for key in self._manifest_keys(prefix):
            artifact = self._load_manifest(key, "cisa_kev_snapshots")
            snapshot = artifact.manifest.get("snapshot", {})
            if snapshot.get("kind") != kind:
                raise S3GoldInputError(f"CISA snapshot kind mismatch: {key}")
            observed = _parse_datetime(snapshot.get("observed_at"), "CISA observed_at")
            if observed <= cutoff.astimezone(UTC):
                candidates.append((observed, key, artifact))
        if not candidates:
            raise S3GoldInputError(f"no committed CISA {kind} snapshot exists before cutoff")
        return max(candidates, key=lambda item: (item[0], item[1]))[2]

    def _select_nvd(self, cutoff: datetime) -> tuple[S3SilverArtifact, ...]:
        prefix = f"{self.prefix}/nvd_cve_windows/"
        selected = []
        for key in self._manifest_keys(prefix):
            artifact = self._load_manifest(key, "nvd_cve_windows")
            manifest = artifact.manifest
            mode = manifest.get("mode")
            if mode not in {"published", "modified"}:
                raise S3GoldInputError(f"unsupported NVD mode in {key}")
            window_end = _parse_datetime(manifest.get("window_end"), "NVD window_end")
            if window_end <= cutoff.astimezone(UTC):
                selected.append((window_end, key, artifact))
        selected.sort(key=lambda item: (item[0], item[1]))
        if not selected or not any(item[2].manifest["mode"] == "published" for item in selected):
            raise S3GoldInputError("no committed NVD published baseline exists before cutoff")
        return tuple(item[2] for item in selected)

    def _load_partition_manifest(self, relative: str, dataset: str) -> S3SilverArtifact:
        key = f"{self.prefix}/{relative}/_manifest.json"
        try:
            return self._load_manifest(key, dataset)
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            if status == 404 or exc.response.get("Error", {}).get("Code") in {
                "NoSuchKey",
                "404",
            }:
                raise S3GoldInputError(
                    f"missing committed Silver manifest: s3://{self.bucket}/{key}"
                ) from exc
            raise

    def _load_manifest(self, key: str, dataset: str) -> S3SilverArtifact:
        response = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"]
        try:
            encoded = body.read()
        finally:
            body.close()
        try:
            manifest = json.loads(encoded)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise S3GoldInputError(f"invalid Silver manifest: s3://{self.bucket}/{key}") from exc
        if not isinstance(manifest, dict) or manifest.get("dataset") != dataset:
            raise S3GoldInputError(f"Silver dataset mismatch: s3://{self.bucket}/{key}")
        parquet = manifest.get("parquet")
        if not isinstance(parquet, dict):
            raise S3GoldInputError(f"Silver manifest has no Parquet contract: {key}")
        filename = parquet.get("file")
        sha256 = parquet.get("sha256")
        size_bytes = parquet.get("size_bytes")
        record_count = manifest.get("record_count")
        if not isinstance(filename, str) or "/" in filename:
            raise S3GoldInputError(f"invalid Silver Parquet filename: {key}")
        if not _SHA256.fullmatch(sha256 or ""):
            raise S3GoldInputError(f"invalid Silver Parquet SHA-256: {key}")
        if not isinstance(size_bytes, int) or size_bytes < 1:
            raise S3GoldInputError(f"invalid Silver Parquet size: {key}")
        if not isinstance(record_count, int) or record_count < 1:
            raise S3GoldInputError(f"invalid Silver record count: {key}")
        if not isinstance(manifest.get("schema_version"), int):
            raise S3GoldInputError(f"invalid Silver schema version: {key}")
        if not isinstance(manifest.get("transform_version"), str):
            raise S3GoldInputError(f"invalid Silver transform version: {key}")
        parquet_key = f"{key.rsplit('/', 1)[0]}/{filename}"
        head = self.s3.head_object(
            Bucket=self.bucket,
            Key=parquet_key,
            ChecksumMode="ENABLED",
        )
        metadata = head.get("Metadata", {})
        checksum = head.get("ChecksumSHA256")
        expected_checksum = base64.b64encode(bytes.fromhex(sha256)).decode()
        checksum_matches = checksum == expected_checksum or metadata.get("sha256") == sha256
        if not checksum_matches and checksum is None and metadata.get("sha256") is None:
            checksum_matches = self._object_sha256(parquet_key) == sha256
        if head.get("ContentLength") != size_bytes or not checksum_matches:
            raise S3GoldInputError(f"Silver Parquet identity mismatch: {parquet_key}")
        return S3SilverArtifact(self.bucket, key, parquet_key, manifest)

    def _object_sha256(self, key: str) -> str:
        response = self.s3.get_object(Bucket=self.bucket, Key=key)
        body = response["Body"]
        digest = hashlib.sha256()
        try:
            while chunk := body.read(1024 * 1024):
                digest.update(chunk)
        finally:
            body.close()
        return digest.hexdigest()

    def _manifest_keys(self, prefix: str):
        paginator = self.s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                key = item.get("Key", "")
                if key.endswith("/_manifest.json"):
                    yield key


def _parse_datetime(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise S3GoldInputError(f"{label} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise S3GoldInputError(f"{label} is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise S3GoldInputError(f"{label} must be timezone-aware")
    return parsed.astimezone(UTC)
