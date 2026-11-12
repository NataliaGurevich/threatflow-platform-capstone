from datetime import UTC, datetime
from hashlib import sha256

import pytest

import threatflow.raw_storage as raw_storage
from threatflow.config import Settings
from threatflow.local_raw_storage import LocalRawArtifactStore
from threatflow.raw_storage import (
    RawArtifactRef,
    calculate_sha256,
    create_raw_artifact_store,
    replicate_validated_artifact,
    store_raw_artifact,
)

ACQUIRED_AT = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def test_calculate_sha256_uses_exact_bytes() -> None:
    content = b'{ "key": 1 }\n'
    assert calculate_sha256(content) == sha256(content).hexdigest()


def test_stores_bytes_and_expected_partition(tmp_path) -> None:
    content = b'{"cve":"CVE-2026-0001"}\n'
    result = store_raw_artifact("cisa_kev", content, ACQUIRED_AT, ".json", raw_data_dir=tmp_path)

    assert result.created is True
    assert result.backend == "local"
    assert result.uri == str(result.path)
    assert result.extension == "json"
    assert result.content_type == "application/json"
    assert result.sha256 == sha256(content).hexdigest()
    assert result.size_bytes == len(content)
    assert result.path == (
        tmp_path / "cisa_kev" / "year=2026" / "month=11" / f"{result.sha256}.json"
    )
    assert result.path.read_bytes() == content


def test_identical_content_reuses_existing_file(tmp_path) -> None:
    first = store_raw_artifact("nvd", b"raw", ACQUIRED_AT, "json", raw_data_dir=tmp_path)
    second = store_raw_artifact("nvd", b"raw", ACQUIRED_AT, "json", raw_data_dir=tmp_path)

    assert first.created is True
    assert second.created is False
    assert second.path == first.path
    assert list(first.path.parent.iterdir()) == [first.path]


def test_changed_content_creates_distinct_artifact(tmp_path) -> None:
    first = store_raw_artifact("epss", b"cve,score\n", ACQUIRED_AT, "csv", raw_data_dir=tmp_path)
    second = store_raw_artifact(
        "epss", b"cve,score\nCVE-1,0.2\n", ACQUIRED_AT, "csv", raw_data_dir=tmp_path
    )

    assert first.path != second.path
    assert first.path.read_bytes() == b"cve,score\n"
    assert second.path.read_bytes() == b"cve,score\nCVE-1,0.2\n"


def test_identical_content_is_reused_across_acquisition_months(tmp_path) -> None:
    first = store_raw_artifact("nvd", b"raw", ACQUIRED_AT, "json", raw_data_dir=tmp_path)
    later = ACQUIRED_AT.replace(month=ACQUIRED_AT.month + 1)
    second = store_raw_artifact("nvd", b"raw", later, "json", raw_data_dir=tmp_path)

    assert second.path == first.path
    assert second.created is False
    assert len(list((tmp_path / "nvd").glob("year=*/month=*/*.json"))) == 1


def test_sources_have_separate_paths(tmp_path) -> None:
    content = b"same bytes"
    cisa = store_raw_artifact("cisa_kev", content, ACQUIRED_AT, "json", raw_data_dir=tmp_path)
    nvd = store_raw_artifact("nvd", content, ACQUIRED_AT, "json", raw_data_dir=tmp_path)

    assert cisa.sha256 == nvd.sha256
    assert cisa.path != nvd.path
    assert cisa.path.read_bytes() == nvd.path.read_bytes() == content


def test_local_store_reads_reference_and_relocated_manifest_path(tmp_path) -> None:
    store = LocalRawArtifactStore(tmp_path)
    artifact = store.store("nvd", b"raw", ACQUIRED_AT, "json")

    assert store.read(artifact) == b"raw"
    relocated = f"/old/machine/data/raw/{artifact.path.relative_to(tmp_path)}"
    assert store.read(relocated) == b"raw"


def test_factory_builds_configured_local_store(tmp_path) -> None:
    store = create_raw_artifact_store(Settings(raw_data_dir=str(tmp_path), _env_file=None))

    assert isinstance(store, LocalRawArtifactStore)
    assert store.root == tmp_path


def test_validated_replication_preserves_exact_logical_identity(tmp_path) -> None:
    content = b'{"cve":"CVE-2026-0001"}\n'
    local = LocalRawArtifactStore(tmp_path).store("nvd", content, ACQUIRED_AT, "json")

    class ReplicaStore:
        backend = "s3"

        def store(self, source, raw, acquired_at, extension, *, content_type=None):
            assert raw == content
            return RawArtifactRef(
                source=source,
                sha256=sha256(raw).hexdigest(),
                uri=f"s3://bronze/bronze/source={source}/sha256={local.sha256}.json",
                extension=extension,
                content_type=content_type,
                size_bytes=len(raw),
                created=True,
                backend="s3",
                bucket="bronze",
                object_key=f"bronze/source={source}/sha256={local.sha256}.json",
            )

    replica = replicate_validated_artifact(ReplicaStore(), local, content, ACQUIRED_AT)

    assert replica is not None
    assert (replica.source, replica.sha256, replica.size_bytes) == (
        local.source,
        local.sha256,
        local.size_bytes,
    )


def test_validated_replication_rejects_changed_identity(tmp_path) -> None:
    local = LocalRawArtifactStore(tmp_path).store("nvd", b"raw", ACQUIRED_AT, "json")

    class WrongReplicaStore:
        backend = "s3"

        def store(self, source, content, acquired_at, extension, *, content_type=None):
            return RawArtifactRef(
                source=source,
                sha256="0" * 64,
                uri="s3://bronze/wrong.json",
                extension=extension,
                content_type=content_type,
                size_bytes=len(content),
                created=True,
                backend="s3",
                bucket="bronze",
                object_key="wrong.json",
            )

    with pytest.raises(ValueError, match="identity"):
        replicate_validated_artifact(WrongReplicaStore(), local, b"raw", ACQUIRED_AT)


def test_previous_local_store_import_path_remains_compatible() -> None:
    assert raw_storage.LocalRawArtifactStore is LocalRawArtifactStore


def test_atomic_publish_cleans_temporary_file_after_failure(tmp_path, monkeypatch) -> None:
    def fail_link(_source, _destination):
        raise OSError("simulated publish failure")

    monkeypatch.setattr("threatflow.local_raw_storage.os.link", fail_link)
    with pytest.raises(OSError, match="simulated publish failure"):
        store_raw_artifact("nvd", b"raw", ACQUIRED_AT, "json", raw_data_dir=tmp_path)

    assert not list(tmp_path.rglob(".tmp-*"))
    assert not list(tmp_path.rglob("*.json"))


@pytest.mark.parametrize(
    ("source", "extension"),
    [("../nvd", "json"), ("unknown", "json"), ("nvd", "csv"), ("epss", "../csv")],
)
def test_rejects_invalid_source_or_extension(tmp_path, source, extension) -> None:
    with pytest.raises(ValueError):
        store_raw_artifact(source, b"raw", ACQUIRED_AT, extension, raw_data_dir=tmp_path)
