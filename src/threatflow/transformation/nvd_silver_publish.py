"""Publish committed local NVD Silver windows to S3 with immutable writes."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.config import Settings
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.nvd_silver import (
    DATASET_NAME,
    MANIFEST_FILE_NAME,
    PARQUET_FILE_NAME,
    verify_committed_nvd_partition,
)
from threatflow.transformation.nvd_window import (
    NvdWindowManifest,
    NvdWindowPage,
    encode_nvd_window_manifest,
)

LOGGER = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NvdSilverPublishCandidate:
    mode: str
    window_id: str
    window_end_path: str
    record_count: int
    parquet_path: Path
    manifest_path: Path
    parquet_sha256: str
    parquet_size_bytes: int


@dataclass(frozen=True)
class NvdSilverPublishResult:
    dry_run: bool
    bucket: str
    prefix: str
    available: int
    selected: int
    verified: int
    planned: int
    uploaded: int
    reused: int
    record_count: int
    uploaded_bytes: int
    target_uris: tuple[str, ...]


def load_nvd_silver_publish_candidates(
    output_root: str | Path,
) -> list[NvdSilverPublishCandidate]:
    dataset_root = Path(output_root) / DATASET_NAME
    if not dataset_root.exists():
        return []
    candidates = []
    pattern = "mode=*/window_end=*/window_id=*/_manifest.json"
    for manifest_path in sorted(dataset_root.glob(pattern)):
        value = _read_manifest(manifest_path)
        mode = manifest_path.parent.parent.parent.name.removeprefix("mode=")
        window_end_path = manifest_path.parent.parent.name.removeprefix("window_end=")
        window_id = manifest_path.parent.name.removeprefix("window_id=")
        if mode not in {"published", "modified"} or not _SHA256.fullmatch(window_id):
            raise ValueError(f"invalid NVD Silver partition path: {manifest_path}")
        if (value.get("mode"), value.get("window_id")) != (mode, window_id):
            raise ValueError(f"NVD Silver manifest identity mismatch: {manifest_path}")
        window = _window_from_silver_manifest(value)
        encoded = encode_nvd_window_manifest(window)
        if calculate_sha256(encoded) != window_id:
            raise ValueError(f"NVD Silver source window SHA mismatch: {manifest_path}")
        committed = verify_committed_nvd_partition(
            output_root=output_root,
            window_content=encoded,
            window_sha256=window_id,
        )
        if committed is None:
            raise RuntimeError(f"NVD Silver partition is not committed: {manifest_path.parent}")
        candidates.append(
            NvdSilverPublishCandidate(
                mode,
                window_id,
                window_end_path,
                committed.record_count,
                Path(committed.parquet_path),
                manifest_path,
                committed.parquet_sha256,
                committed.parquet_size_bytes,
            )
        )
    return candidates


class NvdSilverS3Publisher:
    def __init__(self, bucket: str, prefix: str = "silver", *, client: Any) -> None:
        if not bucket.strip() or not prefix.strip("/"):
            raise ValueError("S3 Silver bucket and prefix must not be empty")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.client = client

    def target_keys(self, candidate: NvdSilverPublishCandidate) -> tuple[str, str]:
        partition = (
            f"{self.prefix}/{DATASET_NAME}/mode={candidate.mode}/"
            f"window_end={candidate.window_end_path}/window_id={candidate.window_id}"
        )
        return f"{partition}/{PARQUET_FILE_NAME}", f"{partition}/{MANIFEST_FILE_NAME}"

    def publish(self, candidate: NvdSilverPublishCandidate) -> tuple[bool, int]:
        parquet_key, manifest_key = self.target_keys(candidate)
        metadata = {
            "dataset": DATASET_NAME,
            "request-mode": candidate.mode,
            "window-sha256": candidate.window_id,
        }
        parquet_created = self._put(
            parquet_key,
            candidate.parquet_path.read_bytes(),
            "application/vnd.apache.parquet",
            candidate.parquet_sha256,
            metadata,
        )
        manifest_content = candidate.manifest_path.read_bytes()
        manifest_created = self._put(
            manifest_key,
            manifest_content,
            "application/json",
            calculate_sha256(manifest_content),
            metadata,
        )
        uploaded_bytes = (
            (candidate.parquet_size_bytes if parquet_created else 0)
            + (len(manifest_content) if manifest_created else 0)
        )
        return manifest_created, uploaded_bytes

    def _put(
        self,
        key: str,
        content: bytes,
        content_type: str,
        sha256: str,
        metadata: dict[str, str],
    ) -> bool:
        expected_metadata = {**metadata, "sha256": sha256}
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                ContentLength=len(content),
                ContentType=content_type,
                ChecksumSHA256=_base64_sha256(sha256),
                Metadata=expected_metadata,
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            created = True
        except ClientError as exc:
            if not _precondition_failed(exc):
                raise
            created = False
        head = self.client.head_object(Bucket=self.bucket, Key=key, ChecksumMode="ENABLED")
        actual_metadata = head.get("Metadata", {})
        if (
            head.get("ContentLength") != len(content)
            or head.get("ContentType") != content_type
            or head.get("ChecksumSHA256") != _base64_sha256(sha256)
            or head.get("ServerSideEncryption") != "AES256"
            or any(actual_metadata.get(name) != value for name, value in expected_metadata.items())
        ):
            raise FileExistsError(f"conflicting NVD Silver object: s3://{self.bucket}/{key}")
        return created


def publish_nvd_silver(
    candidates: list[NvdSilverPublishCandidate],
    *,
    publisher: NvdSilverS3Publisher,
    dry_run: bool,
    limit: int | None = None,
) -> NvdSilverPublishResult:
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    ordered = sorted(
        candidates, key=lambda item: (item.window_end_path, item.mode, item.window_id)
    )
    available = len(ordered)
    selected = ordered[:limit] if limit is not None else ordered
    planned = uploaded = reused = record_count = uploaded_bytes = 0
    uris = []
    for candidate in selected:
        parquet_key, manifest_key = publisher.target_keys(candidate)
        uris.extend(
            [
                f"s3://{publisher.bucket}/{parquet_key}",
                f"s3://{publisher.bucket}/{manifest_key}",
            ]
        )
        record_count += candidate.record_count
        if dry_run:
            planned += 1
            continue
        created, item_bytes = publisher.publish(candidate)
        uploaded += int(created)
        reused += int(not created)
        uploaded_bytes += item_bytes
    return NvdSilverPublishResult(
        dry_run,
        publisher.bucket,
        publisher.prefix,
        available,
        len(selected),
        len(selected),
        planned,
        uploaded,
        reused,
        record_count,
        uploaded_bytes,
        tuple(uris),
    )


def run_nvd_silver_publish(
    settings: Settings,
    *,
    dry_run: bool,
    limit: int | None = None,
    output_root: str | Path | None = None,
    client: Any | None = None,
) -> NvdSilverPublishResult:
    if not settings.s3_silver_bucket:
        raise ValueError("THREATFLOW_S3_SILVER_BUCKET is required")
    candidates = load_nvd_silver_publish_candidates(output_root or settings.silver_data_dir)
    if client is None and not dry_run:
        session = boto3.Session(region_name=settings.aws_region)
        client = session.client(
            "s3",
            config=Config(
                connect_timeout=5,
                read_timeout=60,
                retries={"mode": "standard", "total_max_attempts": 4},
            ),
        )
    publisher = NvdSilverS3Publisher(
        settings.s3_silver_bucket, settings.s3_silver_prefix, client=client
    )
    return publish_nvd_silver(
        candidates, publisher=publisher, dry_run=dry_run, limit=limit
    )


def _window_from_silver_manifest(value: dict[str, Any]) -> NvdWindowManifest:
    source = value.get("source", {})
    try:
        return NvdWindowManifest(
            1,
            "nvd",
            value["mode"],
            datetime.fromisoformat(value["window_start"]),
            datetime.fromisoformat(value["window_end"]),
            datetime.fromisoformat(source["acquired_at"]),
            value["source_record_count"],
            tuple(NvdWindowPage(**page) for page in source["pages"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("invalid NVD Silver source window lineage") from exc


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid NVD Silver manifest: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid NVD Silver manifest object: {path}")
    return value


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _precondition_failed(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 412 or error.get("Code") in {"412", "PreconditionFailed"}


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--dry-run", action="store_true")
    action.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=_positive_int)
    parser.add_argument("--output-root", type=Path)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = run_nvd_silver_publish(
            Settings(),
            dry_run=args.dry_run,
            limit=args.limit,
            output_root=args.output_root,
        )
    except Exception as exc:
        LOGGER.error("NVD Silver publication failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
