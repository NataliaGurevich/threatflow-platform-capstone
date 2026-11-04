"""Immutable, content-addressed storage for original source responses."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from threatflow.config import Settings

_SOURCE_EXTENSIONS = {"cisa_kev": {"json"}, "nvd": {"json"}, "epss": {"csv", "csv.gz"}}
_SAFE_SOURCE = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class RawArtifactResult:
    source: str
    sha256: str
    path: Path
    size_bytes: int
    created: bool


def calculate_sha256(content: bytes) -> str:
    """Return the SHA-256 digest of the exact supplied bytes."""
    return hashlib.sha256(content).hexdigest()


def store_raw_artifact(
    source: str,
    content: bytes,
    acquired_at: datetime,
    extension: str,
    *,
    raw_data_dir: str | Path | None = None,
) -> RawArtifactResult:
    """Store bytes once under their source, acquisition month, and content hash."""
    if not isinstance(source, str) or not _SAFE_SOURCE.fullmatch(source):
        raise ValueError("source must contain only lowercase letters, digits, and underscores")
    if source not in _SOURCE_EXTENSIONS:
        raise ValueError(f"unsupported source: {source}")
    normalized_extension = extension.removeprefix(".").lower()
    if normalized_extension not in _SOURCE_EXTENSIONS[source]:
        raise ValueError(f"unsupported extension for {source}: {extension}")
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes")
    if not isinstance(acquired_at, datetime):
        raise TypeError("acquired_at must be a datetime")

    digest = calculate_sha256(content)
    root = Path(raw_data_dir) if raw_data_dir is not None else Path(Settings().raw_data_dir)
    destination = (
        root
        / source
        / f"year={acquired_at.year:04d}"
        / f"month={acquired_at.month:02d}"
        / f"{digest}.{normalized_extension}"
    )
    existing = next(
        root.glob(f"{source}/year=*/month=*/{digest}.{normalized_extension}"),
        None,
    )
    if existing is not None:
        if existing.read_bytes() != content:
            raise OSError(f"existing artifact does not match its content hash: {existing}")
        return RawArtifactResult(source, digest, existing, len(content), False)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_path: Path | None = None
    created = False
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=".tmp-", delete=False
        ) as tmp:
            temp_path = Path(tmp.name)
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        try:
            # A hard link publishes the complete file atomically and fails if the
            # content-addressed destination already exists, so it cannot overwrite.
            os.link(temp_path, destination)
            created = True
        except FileExistsError:
            if destination.read_bytes() != content:
                raise OSError(
                    f"existing artifact does not match its content hash: {destination}"
                ) from None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

    return RawArtifactResult(source, digest, destination, len(content), created)
