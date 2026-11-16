import base64
import json
from datetime import UTC, datetime
from hashlib import sha256

import pytest
from botocore.exceptions import ClientError

from threatflow.config import Settings
from threatflow.transformation.nvd_silver import NvdSilverPageInput, transform_nvd_window
from threatflow.transformation.nvd_silver_publish import (
    NvdSilverS3Publisher,
    load_nvd_silver_publish_candidates,
    publish_nvd_silver,
    run_nvd_silver_publish,
)
from threatflow.transformation.nvd_window import (
    NvdWindowManifest,
    NvdWindowPage,
    encode_nvd_window_manifest,
)

BUCKET = "silver-test"


def checksum(content):
    return base64.b64encode(sha256(content).digest()).decode()


def create_partition(root):
    page_content = json.dumps(
        {
            "startIndex": 0,
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2022-1234",
                        "published": "2022-01-01T00:00:00Z",
                        "lastModified": "2026-11-01T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "description"}],
                        "metrics": {},
                    }
                }
            ],
        }
    ).encode()
    page = NvdWindowPage(
        0,
        1,
        sha256(page_content).hexdigest(),
        None,
        None,
        None,
        len(page_content),
        "local",
        "data/raw/nvd/page.json",
    )
    window = NvdWindowManifest(
        1,
        "nvd",
        "published",
        datetime(2022, 1, 1, tzinfo=UTC),
        datetime(2022, 1, 8, tzinfo=UTC),
        datetime(2026, 11, 16, tzinfo=UTC),
        1,
        (page,),
    )
    encoded = encode_nvd_window_manifest(window)
    digest = sha256(encoded).hexdigest()
    return transform_nvd_window(
        encoded,
        window_sha256=digest,
        window_uri=f"local-window://{digest}",
        window_version_id=None,
        pages=[NvdSilverPageInput(page, page_content)],
        output_root=root,
    )


class MemoryS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"])
        if parameters.get("IfNoneMatch") == "*" and identity in self.objects:
            raise ClientError(
                {
                    "Error": {"Code": "PreconditionFailed"},
                    "ResponseMetadata": {"HTTPStatusCode": 412},
                },
                "PutObject",
            )
        body = parameters["Body"]
        content = body.read() if hasattr(body, "read") else body
        self.objects[identity] = {
            "content": content,
            "ContentLength": parameters["ContentLength"],
            "ContentType": parameters["ContentType"],
            "ChecksumSHA256": parameters["ChecksumSHA256"],
            "Metadata": parameters["Metadata"],
            "ServerSideEncryption": parameters["ServerSideEncryption"],
        }
        return {}

    def head_object(self, **parameters):
        return {
            key: value
            for key, value in self.objects[(parameters["Bucket"], parameters["Key"])].items()
            if key != "content"
        }


def test_dry_run_verifies_local_commit_without_aws_client(tmp_path):
    create_partition(tmp_path)
    result = run_nvd_silver_publish(
        Settings(s3_silver_bucket=BUCKET, silver_data_dir=str(tmp_path), _env_file=None),
        dry_run=True,
    )
    assert result.available == result.selected == result.planned == 1
    assert result.uploaded == result.reused == 0
    assert len(result.target_uris) == 2


def test_apply_uploads_parquet_then_manifest_and_reuses(tmp_path):
    create_partition(tmp_path)
    candidates = load_nvd_silver_publish_candidates(tmp_path)
    client = MemoryS3()
    publisher = NvdSilverS3Publisher(BUCKET, client=client)

    created = publish_nvd_silver(candidates, publisher=publisher, dry_run=False)
    replay = publish_nvd_silver(candidates, publisher=publisher, dry_run=False)

    assert created.uploaded == 1
    assert replay.reused == 1
    keys = [key for _, key in client.objects]
    assert keys[0].endswith("nvd_cves.parquet")
    assert keys[1].endswith("_manifest.json")


def test_conflicting_existing_object_fails_closed(tmp_path):
    create_partition(tmp_path)
    candidate = load_nvd_silver_publish_candidates(tmp_path)[0]
    client = MemoryS3()
    publisher = NvdSilverS3Publisher(BUCKET, client=client)
    parquet_key, _ = publisher.target_keys(candidate)
    client.objects[(BUCKET, parquet_key)] = {
        "content": b"bad",
        "ContentLength": 3,
        "ContentType": "application/vnd.apache.parquet",
        "ChecksumSHA256": checksum(b"bad"),
        "Metadata": {},
        "ServerSideEncryption": "AES256",
    }
    with pytest.raises(FileExistsError, match="conflicting"):
        publisher.publish(candidate)
