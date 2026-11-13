"""Publish committed local CISA Silver snapshots to S3 with immutable writes."""

from __future__ import annotations

import argparse
import base64
import json
import logging
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from threatflow.config import Settings
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.cisa_silver import (
    DATASET_NAME,
    MANIFEST_FILE_NAME,
    PARQUET_FILE_NAME,
    SnapshotKind,
    verify_committed_cisa_partition,
)

LOGGER = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class CisaSilverPublishCandidate:
    snapshot_kind: SnapshotKind
    snapshot_id: str
    source_sha256: str
    record_count: int
    parquet_path: Path
    manifest_path: Path
    parquet_sha256: str
    parquet_size_bytes: int


@dataclass(frozen=True)
class CisaSilverPublishSelection:
    available: int
    candidates: tuple[CisaSilverPublishCandidate, ...]


@dataclass(frozen=True)
class CisaSilverPublishResult:
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


def load_cisa_silver_publish_candidates(
    output_root: str | Path,
) -> list[CisaSilverPublishCandidate]:
    """Discover and fully verify committed local CISA Silver partitions."""
    dataset_root = Path(output_root) / DATASET_NAME
    if not dataset_root.exists():
        return []
    candidates: list[CisaSilverPublishCandidate] = []
    for manifest_path in sorted(dataset_root.glob("snapshot_kind=*/snapshot_id=*/_manifest.json")):
        kind_part = manifest_path.parent.parent.name
        id_part = manifest_path.parent.name
        snapshot_kind = kind_part.removeprefix("snapshot_kind=")
        snapshot_id = id_part.removeprefix("snapshot_id=")
        if snapshot_kind not in ("snapshot", "git_history"):
            raise ValueError(f"unsupported local CISA Silver snapshot kind: {snapshot_kind}")
        if snapshot_kind == "snapshot" and not _SHA256.fullmatch(snapshot_id):
            raise ValueError(f"invalid current CISA Silver snapshot ID: {snapshot_id}")
        if snapshot_kind == "git_history" and not _GIT_SHA.fullmatch(snapshot_id):
            raise ValueError(f"invalid Git-history CISA Silver snapshot ID: {snapshot_id}")
        manifest = _read_manifest(manifest_path)
        source_sha256 = manifest.get("source", {}).get("sha256")
        record_count = manifest.get("record_count")
        if not _SHA256.fullmatch(source_sha256 or ""):
            raise ValueError(f"invalid source SHA-256 in {manifest_path}")
        if not isinstance(record_count, int) or record_count < 1:
            raise ValueError(f"invalid record count in {manifest_path}")
        committed = verify_committed_cisa_partition(
            output_root=output_root,
            snapshot_kind=snapshot_kind,
            snapshot_id=snapshot_id,
            source_sha256=source_sha256,
            expected_record_count=record_count,
        )
        if committed is None:
            raise RuntimeError(f"CISA Silver partition is not committed: {manifest_path.parent}")
        candidates.append(
            CisaSilverPublishCandidate(
                snapshot_kind=snapshot_kind,
                snapshot_id=snapshot_id,
                source_sha256=source_sha256,
                record_count=record_count,
                parquet_path=Path(committed.parquet_path),
                manifest_path=manifest_path,
                parquet_sha256=committed.parquet_sha256,
                parquet_size_bytes=committed.parquet_size_bytes,
            )
        )
    return candidates


def select_cisa_silver_publish_candidates(
    candidates: list[CisaSilverPublishCandidate], *, limit: int | None = None
) -> CisaSilverPublishSelection:
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    ordered = sorted(candidates, key=lambda item: (item.snapshot_kind, item.snapshot_id))
    return CisaSilverPublishSelection(len(ordered), tuple(ordered[:limit] if limit else ordered))


class CisaSilverS3Publisher:
    def __init__(self, bucket: str, prefix: str = "silver", *, client: Any) -> None:
        if not bucket.strip():
            raise ValueError("S3 Silver bucket must not be empty")
        if not prefix.strip("/"):
            raise ValueError("S3 Silver prefix must not be empty")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.client = client

    def target_keys(self, candidate: CisaSilverPublishCandidate) -> tuple[str, str]:
        partition = (
            f"{self.prefix}/{DATASET_NAME}/snapshot_kind={candidate.snapshot_kind}/"
            f"snapshot_id={candidate.snapshot_id}"
        )
        return f"{partition}/{PARQUET_FILE_NAME}", f"{partition}/{MANIFEST_FILE_NAME}"

    def publish(self, candidate: CisaSilverPublishCandidate) -> tuple[bool, int, tuple[str, str]]:
        parquet_key, manifest_key = self.target_keys(candidate)
        metadata = {
            "dataset": DATASET_NAME,
            "snapshot-kind": candidate.snapshot_kind,
            "snapshot-id": candidate.snapshot_id,
            "source-sha256": candidate.source_sha256,
        }
        parquet_created = self._put_file(
            candidate.parquet_path,
            key=parquet_key,
            content_type="application/vnd.apache.parquet",
            sha256=candidate.parquet_sha256,
            metadata=metadata,
        )
        manifest_content = candidate.manifest_path.read_bytes()
        manifest_sha256 = calculate_sha256(manifest_content)
        manifest_created = self._put_bytes(
            manifest_content,
            key=manifest_key,
            content_type="application/json",
            sha256=manifest_sha256,
            metadata=metadata,
        )
        uploaded_bytes = 0
        if parquet_created:
            uploaded_bytes += candidate.parquet_size_bytes
        if manifest_created:
            uploaded_bytes += len(manifest_content)
        return manifest_created, uploaded_bytes, (
            f"s3://{self.bucket}/{parquet_key}",
            f"s3://{self.bucket}/{manifest_key}",
        )

    def _put_file(
        self, path: Path, *, key: str, content_type: str, sha256: str, metadata: dict[str, str]
    ) -> bool:
        try:
            with path.open("rb") as body:
                self.client.put_object(
                    Bucket=self.bucket,
                    Key=key,
                    Body=body,
                    ContentLength=path.stat().st_size,
                    ContentType=content_type,
                    ChecksumSHA256=_base64_sha256(sha256),
                    Metadata={**metadata, "sha256": sha256},
                    ServerSideEncryption="AES256",
                    IfNoneMatch="*",
                )
            created = True
        except ClientError as exc:
            if not _is_precondition_failed(exc):
                raise
            created = False
        self._verify_object(
            key,
            size_bytes=path.stat().st_size,
            content_type=content_type,
            sha256=sha256,
            metadata=metadata,
        )
        return created

    def _put_bytes(
        self,
        content: bytes,
        *,
        key: str,
        content_type: str,
        sha256: str,
        metadata: dict[str, str],
    ) -> bool:
        try:
            self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content,
                ContentLength=len(content),
                ContentType=content_type,
                ChecksumSHA256=_base64_sha256(sha256),
                Metadata={**metadata, "sha256": sha256},
                ServerSideEncryption="AES256",
                IfNoneMatch="*",
            )
            created = True
        except ClientError as exc:
            if not _is_precondition_failed(exc):
                raise
            created = False
        self._verify_object(
            key,
            size_bytes=len(content),
            content_type=content_type,
            sha256=sha256,
            metadata=metadata,
        )
        return created

    def _verify_object(
        self,
        key: str,
        *,
        size_bytes: int,
        content_type: str,
        sha256: str,
        metadata: dict[str, str],
    ) -> None:
        head = self.client.head_object(Bucket=self.bucket, Key=key, ChecksumMode="ENABLED")
        actual_metadata = head.get("Metadata", {})
        expected_metadata = {**metadata, "sha256": sha256}
        if (
            head.get("ContentLength") != size_bytes
            or head.get("ContentType") != content_type
            or head.get("ChecksumSHA256") != _base64_sha256(sha256)
            or head.get("ServerSideEncryption") != "AES256"
            or any(actual_metadata.get(name) != value for name, value in expected_metadata.items())
        ):
            raise FileExistsError(f"conflicting CISA Silver object: s3://{self.bucket}/{key}")


def publish_cisa_silver(
    selection: CisaSilverPublishSelection,
    *,
    publisher: CisaSilverS3Publisher,
    dry_run: bool,
) -> CisaSilverPublishResult:
    verified = planned = uploaded = reused = record_count = uploaded_bytes = 0
    target_uris: list[str] = []
    for candidate in selection.candidates:
        parquet_key, manifest_key = publisher.target_keys(candidate)
        uris = (
            f"s3://{publisher.bucket}/{parquet_key}",
            f"s3://{publisher.bucket}/{manifest_key}",
        )
        verified += 1
        record_count += candidate.record_count
        if dry_run:
            planned += 1
            target_uris.extend(uris)
            continue
        created, item_bytes, published_uris = publisher.publish(candidate)
        uploaded += created
        reused += not created
        uploaded_bytes += item_bytes
        target_uris.extend(published_uris)
    return CisaSilverPublishResult(
        dry_run,
        publisher.bucket,
        publisher.prefix,
        selection.available,
        len(selection.candidates),
        verified,
        planned,
        uploaded,
        reused,
        record_count,
        uploaded_bytes,
        tuple(target_uris),
    )


def run_cisa_silver_publish(
    settings: Settings,
    *,
    dry_run: bool,
    limit: int | None = None,
    output_root: str | Path | None = None,
    client: Any | None = None,
) -> CisaSilverPublishResult:
    if not settings.s3_silver_bucket:
        raise ValueError("THREATFLOW_S3_SILVER_BUCKET is required")
    candidates = load_cisa_silver_publish_candidates(output_root or settings.silver_data_dir)
    selection = select_cisa_silver_publish_candidates(candidates, limit=limit)
    if client is None and not dry_run:
        client = boto3.client(
            "s3",
            region_name=settings.aws_region,
            config=Config(
                connect_timeout=5,
                read_timeout=60,
                retries={"mode": "standard", "total_max_attempts": 4},
            ),
        )
    publisher = CisaSilverS3Publisher(
        settings.s3_silver_bucket,
        settings.s3_silver_prefix,
        client=client,
    )
    return publish_cisa_silver(selection, publisher=publisher, dry_run=dry_run)


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid CISA Silver manifest: {path}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"invalid CISA Silver manifest object: {path}")
    return value


def _base64_sha256(hex_digest: str) -> str:
    return base64.b64encode(bytes.fromhex(hex_digest)).decode("ascii")


def _is_precondition_failed(exc: ClientError) -> bool:
    error = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return status == 412 or error.get("Code") in {"412", "PreconditionFailed"}


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish committed local CISA Silver to S3.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    parser.add_argument("--limit", type=_positive_int)
    parser.add_argument("--output-root", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        result = run_cisa_silver_publish(
            Settings(), dry_run=args.dry_run, limit=args.limit, output_root=args.output_root
        )
    except Exception as exc:
        LOGGER.error("CISA Silver publication failed: %s", exc)
        return 1
    print(json.dumps(asdict(result), sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
