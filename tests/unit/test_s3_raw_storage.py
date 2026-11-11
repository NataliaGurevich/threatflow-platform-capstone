import base64
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from botocore.stub import Stubber
from pydantic import ValidationError

from threatflow.config import Settings
from threatflow.raw_storage import (
    RawArtifactRef,
    create_raw_artifact_store,
    create_validated_replica_store,
)
from threatflow.s3_raw_storage import RawArtifactIntegrityError, S3RawArtifactStore

BUCKET = "threatflow-dev-bronze-test"
ACQUIRED_AT = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
CONTENT = b'{"cve":"CVE-2026-0001"}\n'
DIGEST = sha256(CONTENT).hexdigest()
CHECKSUM = base64.b64encode(sha256(CONTENT).digest()).decode("ascii")
KEY = f"bronze/source=nvd/sha256={DIGEST}.json"


def _client():
    return boto3.client(
        "s3",
        region_name="eu-central-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        aws_session_token="testing",
    )


def _put_parameters() -> dict:
    return {
        "Bucket": BUCKET,
        "Key": KEY,
        "Body": CONTENT,
        "ContentLength": len(CONTENT),
        "ContentType": "application/json",
        "ChecksumSHA256": CHECKSUM,
        "Metadata": {
            "sha256": DIGEST,
            "source": "nvd",
            "acquired-at": "2026-11-10T12:00:00+00:00",
        },
        "ServerSideEncryption": "AES256",
        "IfNoneMatch": "*",
    }


def _head_parameters(*, version_id: str | None = None) -> dict:
    result = {"Bucket": BUCKET, "Key": KEY, "ChecksumMode": "ENABLED"}
    if version_id is not None:
        result["VersionId"] = version_id
    return result


def _head_response(**overrides) -> dict:
    response = {
        "ContentLength": len(CONTENT),
        "ContentType": "application/json",
        "ChecksumSHA256": CHECKSUM,
        "ServerSideEncryption": "AES256",
        "Metadata": {
            "sha256": DIGEST,
            "source": "nvd",
            "acquired-at": "2026-11-10T12:00:00+00:00",
        },
        "VersionId": "version-1",
    }
    response.update(overrides)
    return response


def test_store_creates_content_addressed_object_and_verifies_head() -> None:
    client = _client()
    with Stubber(client) as stubber:
        stubber.add_response("put_object", {"VersionId": "version-1"}, _put_parameters())
        stubber.add_response(
            "head_object", _head_response(), _head_parameters(version_id="version-1")
        )
        artifact = S3RawArtifactStore(BUCKET, client=client).store(
            "nvd", CONTENT, ACQUIRED_AT, ".json"
        )

    assert artifact.created is True
    assert artifact.backend == "s3"
    assert artifact.uri == f"s3://{BUCKET}/{KEY}"
    assert artifact.bucket == BUCKET
    assert artifact.object_key == KEY
    assert artifact.version_id == "version-1"
    assert artifact.sha256 == DIGEST


def test_store_reuses_only_an_existing_object_with_matching_integrity() -> None:
    client = _client()
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "put_object",
            service_error_code="PreconditionFailed",
            service_message="object already exists",
            http_status_code=412,
            expected_params=_put_parameters(),
        )
        stubber.add_response("head_object", _head_response(), _head_parameters())
        artifact = S3RawArtifactStore(BUCKET, client=client).store(
            "nvd", CONTENT, ACQUIRED_AT, "json"
        )

    assert artifact.created is False
    assert artifact.version_id == "version-1"


def test_store_rejects_existing_object_with_wrong_checksum() -> None:
    client = _client()
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "put_object",
            service_error_code="PreconditionFailed",
            http_status_code=412,
            expected_params=_put_parameters(),
        )
        stubber.add_response(
            "head_object",
            _head_response(ChecksumSHA256=base64.b64encode(b"wrong").decode("ascii")),
            _head_parameters(),
        )
        with pytest.raises(RawArtifactIntegrityError, match="ChecksumSHA256"):
            S3RawArtifactStore(BUCKET, client=client).store(
                "nvd", CONTENT, ACQUIRED_AT, "json"
            )


def test_store_propagates_non_idempotency_s3_error() -> None:
    client = _client()
    with Stubber(client) as stubber:
        stubber.add_client_error(
            "put_object",
            service_error_code="AccessDenied",
            http_status_code=403,
            expected_params=_put_parameters(),
        )
        with pytest.raises(ClientError, match="AccessDenied"):
            S3RawArtifactStore(BUCKET, client=client).store(
                "nvd", CONTENT, ACQUIRED_AT, "json"
            )


def test_read_closes_stream_and_verifies_manifest_hash() -> None:
    client = _client()
    store = S3RawArtifactStore(BUCKET, client=client)
    raw_stream = BytesIO(CONTENT)
    body = StreamingBody(raw_stream, len(CONTENT))
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_object",
            {"Body": body, "ContentLength": len(CONTENT)},
            {"Bucket": BUCKET, "Key": KEY, "VersionId": "version-1"},
        )
        artifact = RawArtifactRef(
            source="nvd",
            sha256=DIGEST,
            uri=f"s3://{BUCKET}/{KEY}",
            extension="json",
            content_type="application/json",
            size_bytes=len(CONTENT),
            created=False,
            backend="s3",
            bucket=BUCKET,
            object_key=KEY,
            version_id="version-1",
        )
        assert store.read(artifact) == CONTENT

    assert raw_stream.closed is True


def test_read_rejects_downloaded_bytes_that_do_not_match_manifest() -> None:
    client = _client()
    store = S3RawArtifactStore(BUCKET, client=client)
    corrupt = b"x" * len(CONTENT)
    body = StreamingBody(BytesIO(corrupt), len(corrupt))
    artifact = RawArtifactRef(
        source="nvd",
        sha256=DIGEST,
        uri=f"s3://{BUCKET}/{KEY}",
        extension="json",
        content_type="application/json",
        size_bytes=len(CONTENT),
        created=False,
        backend="s3",
        bucket=BUCKET,
        object_key=KEY,
    )
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_object",
            {"Body": body, "ContentLength": len(corrupt)},
            {"Bucket": BUCKET, "Key": KEY},
        )
        with pytest.raises(RawArtifactIntegrityError, match="SHA-256"):
            store.read(artifact)


def test_read_rejects_locator_outside_configured_bucket_or_prefix() -> None:
    store = S3RawArtifactStore(BUCKET, client=_client())

    with pytest.raises(ValueError, match="configured bucket"):
        store.read(f"s3://other-bucket/{KEY}")
    with pytest.raises(ValueError, match="outside configured prefix"):
        store.read(f"s3://{BUCKET}/other/{KEY}")


def test_s3_settings_require_bucket_and_factory_builds_s3_store(monkeypatch) -> None:
    with pytest.raises(ValidationError, match="s3_bronze_bucket"):
        Settings(raw_storage_backend="s3")

    fake_client = object()
    monkeypatch.setattr(
        "threatflow.s3_raw_storage.boto3.client", lambda *args, **kwargs: fake_client
    )
    store = create_raw_artifact_store(
        Settings(
            raw_storage_backend="s3",
            s3_bronze_bucket=BUCKET,
            s3_bronze_prefix="/bronze/",
            aws_region="eu-central-1",
        )
    )

    assert isinstance(store, S3RawArtifactStore)
    assert store.bucket == BUCKET
    assert store.prefix == "bronze"
    assert store.client is fake_client


def test_replication_settings_require_local_primary_and_build_s3_target(monkeypatch) -> None:
    with pytest.raises(ValidationError, match="s3_bronze_bucket"):
        Settings(s3_replication_enabled=True)
    with pytest.raises(ValidationError, match="raw_storage_backend='local'"):
        Settings(
            raw_storage_backend="s3",
            s3_replication_enabled=True,
            s3_bronze_bucket=BUCKET,
        )

    fake_client = object()
    monkeypatch.setattr(
        "threatflow.s3_raw_storage.boto3.client", lambda *args, **kwargs: fake_client
    )
    store = create_validated_replica_store(
        Settings(s3_replication_enabled=True, s3_bronze_bucket=BUCKET)
    )

    assert isinstance(store, S3RawArtifactStore)
    assert store.client is fake_client
    assert create_validated_replica_store(Settings()) is None
