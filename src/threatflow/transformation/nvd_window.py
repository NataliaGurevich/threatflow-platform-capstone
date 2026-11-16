"""Immutable commit contract for one complete paginated NVD API window."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from threatflow.raw_storage import RawArtifactRef, RawArtifactStore, calculate_sha256

NvdMode = Literal["published", "modified"]
WINDOW_SCHEMA_VERSION = 1
WINDOW_EXTENSION = ".window.json"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class NvdWindowPage:
    start_index: int
    record_count: int
    sha256: str
    bucket: str | None
    key: str | None
    version_id: str | None
    size_bytes: int
    backend: str = "s3"
    uri: str | None = None


@dataclass(frozen=True)
class NvdWindowManifest:
    schema_version: int
    source: str
    mode: NvdMode
    requested_start: datetime
    requested_end: datetime
    acquired_at: datetime
    total_results: int
    pages: tuple[NvdWindowPage, ...]

    @property
    def record_count(self) -> int:
        return sum(page.record_count for page in self.pages)


def build_nvd_window_manifest(
    *,
    mode: NvdMode,
    requested_start: datetime,
    requested_end: datetime,
    acquired_at: datetime,
    total_results: int,
    pages: list[tuple[RawArtifactRef, int, int]],
) -> NvdWindowManifest:
    """Build and validate a complete ordered NVD page-set manifest."""
    manifest = NvdWindowManifest(
        schema_version=WINDOW_SCHEMA_VERSION,
        source="nvd",
        mode=mode,
        requested_start=requested_start,
        requested_end=requested_end,
        acquired_at=acquired_at,
        total_results=total_results,
        pages=tuple(
            NvdWindowPage(
                start_index=start_index,
                record_count=record_count,
                sha256=artifact.sha256,
                bucket=artifact.bucket or "",
                key=artifact.object_key or "",
                version_id=artifact.version_id or "",
                size_bytes=artifact.size_bytes,
                backend=artifact.backend,
                uri=artifact.uri,
            )
            for artifact, start_index, record_count in pages
        ),
    )
    validate_nvd_window_manifest(manifest)
    return manifest


def encode_nvd_window_manifest(manifest: NvdWindowManifest) -> bytes:
    validate_nvd_window_manifest(manifest)
    payload = asdict(manifest)
    for name in ("requested_start", "requested_end", "acquired_at"):
        payload[name] = payload[name].astimezone(UTC).isoformat().replace("+00:00", "Z")
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_nvd_window_manifest(content: bytes) -> NvdWindowManifest:
    try:
        value = json.loads(content)
        pages = tuple(NvdWindowPage(**page) for page in value["pages"])
        manifest = NvdWindowManifest(
            schema_version=value["schema_version"],
            source=value["source"],
            mode=value["mode"],
            requested_start=_timestamp(value["requested_start"]),
            requested_end=_timestamp(value["requested_end"]),
            acquired_at=_timestamp(value["acquired_at"]),
            total_results=value["total_results"],
            pages=pages,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid NVD window manifest") from exc
    validate_nvd_window_manifest(manifest)
    return manifest


def publish_nvd_window_manifest(
    store: RawArtifactStore,
    manifest: NvdWindowManifest,
) -> RawArtifactRef:
    """Publish the window manifest only after every referenced page is complete."""
    content = encode_nvd_window_manifest(manifest)
    return store.store(
        "nvd",
        content,
        manifest.acquired_at,
        WINDOW_EXTENSION,
        content_type="application/json",
        metadata={
            "artifact-kind": "window-manifest",
            "request-mode": manifest.mode,
            "requested-start": manifest.requested_start.astimezone(UTC).isoformat(),
            "requested-end": manifest.requested_end.astimezone(UTC).isoformat(),
            "record-count": str(manifest.record_count),
            "page-count": str(len(manifest.pages)),
        },
    )


def validate_nvd_window_manifest(manifest: NvdWindowManifest) -> None:
    if manifest.schema_version != WINDOW_SCHEMA_VERSION or manifest.source != "nvd":
        raise ValueError("unsupported NVD window manifest schema or source")
    if manifest.mode not in ("published", "modified"):
        raise ValueError("NVD window mode must be published or modified")
    for value in (manifest.requested_start, manifest.requested_end, manifest.acquired_at):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("NVD window timestamps must be timezone-aware")
    if manifest.requested_start >= manifest.requested_end:
        raise ValueError("NVD window start must be before end")
    if type(manifest.total_results) is not int or manifest.total_results < 0:
        raise ValueError("NVD window total_results must be a non-negative integer")
    if not manifest.pages:
        raise ValueError("NVD window must contain at least one page")
    expected_start = 0
    for page in manifest.pages:
        if page.start_index != expected_start or page.record_count < 0:
            raise ValueError("NVD window pages are not contiguous")
        if not _SHA256.fullmatch(page.sha256):
            raise ValueError("NVD window page SHA-256 is invalid")
        if page.size_bytes < 1 or page.backend not in {"s3", "local"}:
            raise ValueError("NVD window page lineage is invalid")
        if page.backend == "s3" and (
            not page.bucket or not page.key or not page.version_id
        ):
            raise ValueError("NVD window page is missing exact S3 lineage")
        if page.backend == "local" and (
            not page.uri or page.bucket or page.key or page.version_id
        ):
            raise ValueError("NVD local window page lineage is invalid")
        expected_start += page.record_count
    if expected_start != manifest.total_results:
        raise ValueError("NVD window page counts do not match total_results")


def window_sha256(manifest: NvdWindowManifest) -> str:
    return calculate_sha256(encode_nvd_window_manifest(manifest))


def manifest_identity(manifest: NvdWindowManifest) -> tuple[Any, ...]:
    return (
        manifest.mode,
        manifest.requested_start,
        manifest.requested_end,
        manifest.total_results,
        tuple((page.sha256, page.version_id) for page in manifest.pages),
    )


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)
