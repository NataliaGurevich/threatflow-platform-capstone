from datetime import UTC, datetime

import pytest

from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.raw_storage_reconciliation import (
    ReconciliationCandidate,
    reconcile_candidates,
)
from threatflow.s3_raw_storage import build_s3_object_key

ACQUIRED_AT = datetime(2026, 11, 11, 10, 0, tzinfo=UTC)
BUCKET = "threatflow-bronze"


def candidate(artifact_id: int, content: bytes) -> ReconciliationCandidate:
    return ReconciliationCandidate(
        artifact_id=artifact_id,
        source="epss",
        sha256=calculate_sha256(content),
        extension="csv.gz",
        size_bytes=len(content),
        acquired_at=ACQUIRED_AT,
        local_uri=f"memory://artifact-{artifact_id}",
    )


class MemoryLocalStore:
    backend = "local"

    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        uri = artifact.uri if isinstance(artifact, RawArtifactRef) else artifact
        if uri not in self.objects:
            raise FileNotFoundError(uri)
        return self.objects[uri]

    def store(self, *args, **kwargs):
        raise AssertionError("local store must not write during reconciliation")


class MemoryS3Store:
    backend = "s3"

    def __init__(self, *, fail_content: bytes | None = None, created: bool = True):
        self.fail_content = fail_content
        self.created = created
        self.calls: list[bytes] = []

    def store(self, source, content, acquired_at, extension, *, content_type=None):
        self.calls.append(content)
        if content == self.fail_content:
            raise OSError("simulated S3 failure")
        digest = calculate_sha256(content)
        key = build_s3_object_key("bronze", source, digest, extension)
        return RawArtifactRef(
            source=source,
            sha256=digest,
            uri=f"s3://{BUCKET}/{key}",
            extension=extension,
            content_type=content_type or "application/gzip",
            size_bytes=len(content),
            created=self.created,
            backend="s3",
            bucket=BUCKET,
            object_key=key,
            version_id="version-1",
        )

    def read(self, artifact):
        raise AssertionError("S3 read is not needed during reconciliation")


def test_dry_run_validates_local_bytes_without_using_s3() -> None:
    good = candidate(1, b"good")
    corrupt = candidate(2, b"expected")
    local = MemoryLocalStore(
        {
            good.local_uri: b"good",
            corrupt.local_uri: b"corrupt!",
        }
    )

    result = reconcile_candidates(
        [good, corrupt],
        source="epss",
        bucket=BUCKET,
        prefix="bronze",
        local_store=local,
        dry_run=True,
    )

    assert result.scanned == 2
    assert result.verified == result.planned == 1
    assert result.uploaded == result.reused == 0
    assert result.total_bytes == len(b"good")
    assert result.target_uris == (
        f"s3://{BUCKET}/bronze/source=epss/sha256={good.sha256}.csv.gz",
    )
    assert len(result.issues) == 1
    assert "SHA-256 mismatch" in result.issues[0].message


def test_apply_commits_prior_location_and_retry_can_resume_after_failure() -> None:
    first = candidate(1, b"first")
    second = candidate(2, b"second")
    local = MemoryLocalStore({first.local_uri: b"first", second.local_uri: b"second"})
    failing_s3 = MemoryS3Store(fail_content=b"second")
    persisted: list[int] = []

    def persist(item, location, verified_at):
        assert location.backend == "s3"
        assert verified_at.tzinfo is not None
        persisted.append(item.artifact_id)

    with pytest.raises(OSError, match="simulated S3 failure"):
        reconcile_candidates(
            [first, second],
            source="epss",
            bucket=BUCKET,
            prefix="bronze",
            local_store=local,
            dry_run=False,
            target_store=failing_s3,
            record_location=persist,
        )

    assert persisted == [first.artifact_id]
    successful_retry = reconcile_candidates(
        [second],
        source="epss",
        bucket=BUCKET,
        prefix="bronze",
        local_store=local,
        dry_run=False,
        target_store=MemoryS3Store(created=False),
        record_location=persist,
    )
    assert persisted == [first.artifact_id, second.artifact_id]
    assert successful_retry.uploaded == 0
    assert successful_retry.reused == 1


def test_empty_plan_preserves_requested_source() -> None:
    result = reconcile_candidates(
        [],
        source="nvd",
        bucket=BUCKET,
        prefix="bronze",
        local_store=MemoryLocalStore({}),
        dry_run=True,
    )

    assert result.source == "nvd"
    assert result.scanned == result.planned == 0
