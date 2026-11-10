"""Backend-neutral contract for immutable original source responses."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol

from threatflow.config import Settings

_SOURCE_EXTENSIONS = {"cisa_kev": {"json"}, "nvd": {"json"}, "epss": {"csv", "csv.gz"}}
_SAFE_SOURCE = re.compile(r"^[a-z][a-z0-9_]*$")
_CONTENT_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "csv.gz": "application/gzip",
}


@dataclass(frozen=True)
class RawArtifactRef:
    """Backend-neutral reference to one immutable raw artifact."""

    source: str
    sha256: str
    uri: str
    extension: str
    content_type: str
    size_bytes: int
    created: bool
    backend: str

    @property
    def path(self) -> Path:
        """Return the local path while the compatibility API is in use."""
        if self.backend != "local":
            raise ValueError(f"artifact backend {self.backend!r} has no local path")
        return Path(self.uri)


# Compatibility name retained for repository and third-party imports.
RawArtifactResult = RawArtifactRef


class RawArtifactStore(Protocol):
    """Store and retrieve exact raw bytes without exposing backend SDK details."""

    def store(
        self,
        source: str,
        content: bytes,
        acquired_at: datetime,
        extension: str,
        *,
        content_type: str | None = None,
    ) -> RawArtifactRef: ...

    def read(self, artifact: RawArtifactRef | str) -> bytes: ...


def calculate_sha256(content: bytes) -> str:
    """Return the SHA-256 digest of the exact supplied bytes."""
    return hashlib.sha256(content).hexdigest()


class LocalRawArtifactStore:
    """Atomic, content-addressed raw storage on a local filesystem."""

    backend = "local"

    def __init__(self, raw_data_dir: str | Path):
        self.root = Path(raw_data_dir)

    def store(
        self,
        source: str,
        content: bytes,
        acquired_at: datetime,
        extension: str,
        *,
        content_type: str | None = None,
    ) -> RawArtifactRef:
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

        resolved_content_type = content_type or _CONTENT_TYPES[normalized_extension]
        digest = calculate_sha256(content)
        destination = (
            self.root
            / source
            / f"year={acquired_at.year:04d}"
            / f"month={acquired_at.month:02d}"
            / f"{digest}.{normalized_extension}"
        )
        existing = next(
            self.root.glob(f"{source}/year=*/month=*/{digest}.{normalized_extension}"),
            None,
        )
        if existing is not None:
            if existing.read_bytes() != content:
                raise OSError(f"existing artifact does not match its content hash: {existing}")
            return RawArtifactRef(
                source,
                digest,
                str(existing),
                normalized_extension,
                resolved_content_type,
                len(content),
                False,
                self.backend,
            )
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

        return RawArtifactRef(
            source,
            digest,
            str(destination),
            normalized_extension,
            resolved_content_type,
            len(content),
            created,
            self.backend,
        )

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        """Read a local locator, including one recorded under a previous raw root."""
        locator = artifact.uri if isinstance(artifact, RawArtifactRef) else artifact
        stored = Path(locator)
        if stored.is_file():
            return stored.read_bytes()

        for source in _SOURCE_EXTENSIONS:
            try:
                source_index = stored.parts.index(source)
            except ValueError:
                continue
            candidate = self.root.joinpath(*stored.parts[source_index:])
            if candidate.is_file():
                return candidate.read_bytes()
        raise FileNotFoundError(f"cannot resolve raw artifact: {locator}")


def create_raw_artifact_store(settings: Settings | None = None) -> RawArtifactStore:
    """Build the configured raw storage backend."""
    settings = settings or Settings()
    if settings.raw_storage_backend == "local":
        return LocalRawArtifactStore(settings.raw_data_dir)
    raise ValueError(f"unsupported raw storage backend: {settings.raw_storage_backend}")


def store_raw_artifact(
    source: str,
    content: bytes,
    acquired_at: datetime,
    extension: str,
    *,
    raw_data_dir: str | Path | None = None,
) -> RawArtifactResult:
    """Compatibility wrapper around :class:`LocalRawArtifactStore`."""
    root = Path(raw_data_dir) if raw_data_dir is not None else Path(Settings().raw_data_dir)
    return LocalRawArtifactStore(root).store(source, content, acquired_at, extension)
