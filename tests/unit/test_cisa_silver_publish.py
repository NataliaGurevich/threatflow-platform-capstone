import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from threatflow.config import Settings
from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.cisa_silver import transform_cisa_bytes
from threatflow.transformation.cisa_silver_publish import (
    CisaSilverS3Publisher,
    load_cisa_silver_publish_candidates,
    publish_cisa_silver,
    run_cisa_silver_publish,
    select_cisa_silver_publish_candidates,
)

BUCKET = "threatflow-silver-test"
ACQUIRED_AT = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)


def catalog_bytes(cve="CVE-2026-1234"):
    return json.dumps(
        {
            "catalogVersion": "2026.11.13",
            "dateReleased": "2026-11-13T09:00:00Z",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": cve,
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Issue",
                    "dateAdded": "2026-11-01",
                    "shortDescription": "Description",
                    "requiredAction": "Patch",
                    "dueDate": "2026-11-20",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ],
        }
    ).encode()


def create_partition(root, content=None):
    content = content or catalog_bytes()
    return transform_cisa_bytes(
        content,
        snapshot_kind="snapshot",
        source_sha256=calculate_sha256(content),
        source_uri="s3://bronze/source.json",
        source_version_id="bronze-version-1",
        acquired_at=ACQUIRED_AT,
        output_root=root,
    )


class MemoryS3:
    def __init__(self, *, fail_key_suffix=None):
        self.objects = {}
        self.fail_key_suffix = fail_key_suffix

    def put_object(self, **parameters):
        key = (parameters["Bucket"], parameters["Key"])
        if self.fail_key_suffix and parameters["Key"].endswith(self.fail_key_suffix):
            raise ClientError(
                {
                    "Error": {"Code": "ServiceUnavailable"},
                    "ResponseMetadata": {"HTTPStatusCode": 503},
                },
                "PutObject",
            )
        if key in self.objects and parameters.get("IfNoneMatch") == "*":
            raise ClientError(
                {
                    "Error": {"Code": "PreconditionFailed"},
                    "ResponseMetadata": {"HTTPStatusCode": 412},
                },
                "PutObject",
            )
        body = parameters["Body"]
        content = body.read() if hasattr(body, "read") else body
        self.objects[key] = {
            "content": content,
            "ContentLength": parameters["ContentLength"],
            "ContentType": parameters["ContentType"],
            "ChecksumSHA256": parameters["ChecksumSHA256"],
            "Metadata": parameters["Metadata"],
            "ServerSideEncryption": parameters["ServerSideEncryption"],
        }
        return {"VersionId": "version-1"}

    def head_object(self, **parameters):
        return {
            name: value
            for name, value in self.objects[(parameters["Bucket"], parameters["Key"])].items()
            if name != "content"
        }


def test_dry_run_discovers_and_verifies_without_creating_aws_client(tmp_path):
    create_partition(tmp_path)
    result = run_cisa_silver_publish(
        Settings(
            s3_silver_bucket=BUCKET,
            s3_silver_prefix="silver",
            silver_data_dir=str(tmp_path),
            _env_file=None,
        ),
        dry_run=True,
    )
    assert result.available == result.selected == result.verified == result.planned == 1
    assert result.uploaded == result.reused == 0
    assert len(result.target_uris) == 2
    assert result.target_uris[0].startswith(f"s3://{BUCKET}/silver/cisa_kev_snapshots/")


def test_apply_uploads_parquet_then_manifest_and_replay_reuses(tmp_path):
    local = create_partition(tmp_path)
    candidates = load_cisa_silver_publish_candidates(tmp_path)
    selection = select_cisa_silver_publish_candidates(candidates)
    client = MemoryS3()
    publisher = CisaSilverS3Publisher(BUCKET, client=client)

    first = publish_cisa_silver(selection, publisher=publisher, dry_run=False)
    assert first.uploaded == 1
    assert first.reused == 0
    assert first.uploaded_bytes == Path(local.parquet_path).stat().st_size + Path(
        local.manifest_path
    ).stat().st_size
    keys = [key for _, key in client.objects]
    assert keys[0].endswith("cisa_kev.parquet")
    assert keys[1].endswith("_manifest.json")

    replay = publish_cisa_silver(selection, publisher=publisher, dry_run=False)
    assert replay.uploaded == 0
    assert replay.reused == 1
    assert replay.uploaded_bytes == 0


def test_existing_conflicting_object_is_rejected(tmp_path):
    create_partition(tmp_path)
    candidate = load_cisa_silver_publish_candidates(tmp_path)[0]
    client = MemoryS3()
    publisher = CisaSilverS3Publisher(BUCKET, client=client)
    parquet_key, _ = publisher.target_keys(candidate)
    client.objects[(BUCKET, parquet_key)] = {
        "content": b"wrong",
        "ContentLength": 5,
        "ContentType": "application/vnd.apache.parquet",
        "ChecksumSHA256": "wrong",
        "Metadata": {},
        "ServerSideEncryption": "AES256",
    }
    with pytest.raises(FileExistsError, match="conflicting"):
        publisher.publish(candidate)


def test_failure_after_parquet_is_retryable(tmp_path):
    create_partition(tmp_path)
    selection = select_cisa_silver_publish_candidates(
        load_cisa_silver_publish_candidates(tmp_path)
    )
    client = MemoryS3(fail_key_suffix="_manifest.json")
    publisher = CisaSilverS3Publisher(BUCKET, client=client)
    with pytest.raises(ClientError, match="ServiceUnavailable"):
        publish_cisa_silver(selection, publisher=publisher, dry_run=False)
    assert len(client.objects) == 1

    client.fail_key_suffix = None
    retry = publish_cisa_silver(selection, publisher=publisher, dry_run=False)
    assert retry.uploaded == 1
    assert len(client.objects) == 2


def test_local_tampering_and_missing_configuration_fail(tmp_path):
    local = create_partition(tmp_path)
    Path(local.parquet_path).write_bytes(b"corrupt")
    with pytest.raises(Exception, match="Parquet"):
        load_cisa_silver_publish_candidates(tmp_path)
    with pytest.raises(ValueError, match="SILVER_BUCKET"):
        run_cisa_silver_publish(Settings(_env_file=None), dry_run=True, output_root=tmp_path)
