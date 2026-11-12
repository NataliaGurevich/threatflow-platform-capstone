from datetime import UTC, datetime

import pytest

from threatflow.models.raw_artifact import RawArtifact, RawArtifactLocation
from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.raw_storage_restore import restore_artifact

ACQUIRED_AT = datetime(2026, 11, 12, 10, 0, tzinfo=UTC)


class MemoryS3Store:
    backend = "s3"

    def __init__(self, content: bytes):
        self.content = content
        self.read_ref: RawArtifactRef | None = None

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        assert isinstance(artifact, RawArtifactRef)
        self.read_ref = artifact
        return self.content

    def store(self, *args, **kwargs):
        raise AssertionError("restore must not write to S3")


class MemoryLocalStore:
    backend = "local"

    def __init__(self):
        self.calls: list[bytes] = []

    def store(self, source, content, acquired_at, extension, *, content_type=None):
        self.calls.append(content)
        return RawArtifactRef(
            source=source,
            sha256=calculate_sha256(content),
            uri=f"memory://{source}/{calculate_sha256(content)}.{extension}",
            extension=extension,
            content_type=content_type or "application/json",
            size_bytes=len(content),
            created=True,
            backend="local",
        )

    def read(self, artifact):
        raise AssertionError("local read is not needed during restore")


def manifest(content: bytes) -> tuple[RawArtifact, RawArtifactLocation]:
    digest = calculate_sha256(content)
    artifact = RawArtifact(
        id=7,
        source="cisa_kev",
        sha256=digest,
        storage_path="data/raw/cisa_kev/missing.json",
        extension="json",
        size_bytes=len(content),
        first_acquired_at=ACQUIRED_AT,
        last_seen_at=ACQUIRED_AT,
    )
    location = RawArtifactLocation(
        artifact_id=7,
        backend="s3",
        uri=f"s3://threatflow-bronze/bronze/source=cisa_kev/sha256={digest}.json",
        storage_bucket="threatflow-bronze",
        storage_key=f"bronze/source=cisa_kev/sha256={digest}.json",
        storage_version_id="version-1",
        first_recorded_at=ACQUIRED_AT,
        last_verified_at=ACQUIRED_AT,
    )
    return artifact, location


def test_restore_verifies_s3_identity_and_publishes_exact_local_bytes() -> None:
    content = b'{"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}'
    artifact, location = manifest(content)
    s3_store = MemoryS3Store(content)
    local_store = MemoryLocalStore()

    restored = restore_artifact(
        artifact,
        location,
        s3_store=s3_store,
        local_store=local_store,
    )

    assert local_store.calls == [content]
    assert restored.sha256 == artifact.sha256
    assert restored.size_bytes == artifact.size_bytes
    assert s3_store.read_ref is not None
    assert s3_store.read_ref.version_id == "version-1"


def test_restore_rejects_corrupt_download_before_local_write() -> None:
    artifact, location = manifest(b"expected")
    local_store = MemoryLocalStore()

    with pytest.raises(OSError, match="SHA-256 mismatch"):
        restore_artifact(
            artifact,
            location,
            s3_store=MemoryS3Store(b"corrupt!"),
            local_store=local_store,
        )

    assert local_store.calls == []
