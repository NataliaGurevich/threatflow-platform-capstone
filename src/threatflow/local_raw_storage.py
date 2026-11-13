"""Local filesystem implementation of immutable raw artifact storage."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from threatflow.raw_storage import (
    RawArtifactRef,
    calculate_sha256,
    supported_raw_sources,
    validate_raw_artifact_input,
)


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
        metadata: Mapping[str, str] | None = None,
    ) -> RawArtifactRef:
        """Store bytes once under their source, acquisition month, and content hash."""
        del metadata
        normalized_extension, resolved_content_type = validate_raw_artifact_input(
            source, content, acquired_at, extension, content_type
        )
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
                source=source,
                sha256=digest,
                uri=str(existing),
                extension=normalized_extension,
                content_type=resolved_content_type,
                size_bytes=len(content),
                created=False,
                backend=self.backend,
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
            source=source,
            sha256=digest,
            uri=str(destination),
            extension=normalized_extension,
            content_type=resolved_content_type,
            size_bytes=len(content),
            created=created,
            backend=self.backend,
        )

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        """Read a local locator, including one recorded under a previous raw root."""
        locator = artifact.uri if isinstance(artifact, RawArtifactRef) else artifact
        stored = Path(locator)
        if stored.is_file():
            return stored.read_bytes()

        for source in supported_raw_sources():
            try:
                source_index = stored.parts.index(source)
            except ValueError:
                continue
            candidate = self.root.joinpath(*stored.parts[source_index:])
            if candidate.is_file():
                return candidate.read_bytes()
        raise FileNotFoundError(f"cannot resolve raw artifact: {locator}")
