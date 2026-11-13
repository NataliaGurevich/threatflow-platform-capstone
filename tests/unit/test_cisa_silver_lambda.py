import base64
import json
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from threatflow.transformation.cisa_silver_lambda import (
    CisaSilverLambdaConfig,
    CisaSilverS3Processor,
    lambda_handler,
    process_s3_notification,
)

BRONZE_BUCKET = "threatflow-bronze-test"
SILVER_BUCKET = "threatflow-silver-test"
VERSION_ID = "bronze-version-1"
FIXTURE = Path("tests/fixtures/aws/s3_cisa_object_created.json")


def raw(records=2):
    vulnerabilities = []
    for index in range(records):
        vulnerabilities.append(
            {
                "cveID": f"CVE-2026-{index + 1000}",
                "vendorProject": "Vendor",
                "product": "Product",
                "vulnerabilityName": "Issue",
                "dateAdded": "2026-11-01",
                "shortDescription": "Description",
                "requiredAction": "Patch",
                "dueDate": "2026-11-20",
                "knownRansomwareCampaignUse": "Unknown",
            }
        )
    return json.dumps(
        {
            "catalogVersion": "2026.11.13",
            "dateReleased": "2026-11-13T09:00:00Z",
            "count": records,
            "vulnerabilities": vulnerabilities,
        }
    ).encode()


def event(content):
    value = json.loads(FIXTURE.read_text())
    item = value["Records"][0]["s3"]["object"]
    item["key"] = item["key"].replace("REPLACE_SHA256", sha256(content).hexdigest())
    item["size"] = len(content)
    return value


def checksum(content):
    return base64.b64encode(sha256(content).digest()).decode()


def client_error(code, status, operation):
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        operation,
    )


class MemoryS3:
    def __init__(self, content):
        self.objects = {}
        self.put_calls = []
        digest = sha256(content).hexdigest()
        key = f"bronze/source=cisa_kev/sha256={digest}.json"
        self.objects[(BRONZE_BUCKET, key, VERSION_ID)] = {
            "content": content,
            "metadata": {
                "source": "cisa_kev",
                "sha256": digest,
                "acquired-at": "2026-11-13T10:00:00+00:00",
                "request-mode": "snapshot",
                "record-count": str(json.loads(content)["count"]),
            },
            "content_type": "application/json",
            "checksum": checksum(content),
            "encryption": "AES256",
            "etag": '"bronze-etag"',
        }

    def get_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"], parameters.get("VersionId"))
        stored = self.objects.get(identity)
        if stored is None and parameters.get("VersionId") is None:
            stored = self.objects.get((parameters["Bucket"], parameters["Key"], None))
        if stored is None:
            raise client_error("NoSuchKey", 404, "GetObject")
        content = stored["content"]
        response = {
            "Body": StreamingBody(BytesIO(content), len(content)),
            "ContentLength": len(content),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": stored["encryption"],
            "ETag": stored["etag"],
        }
        if parameters.get("VersionId"):
            response["VersionId"] = parameters["VersionId"]
        return response

    def put_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"], None)
        existing = self.objects.get(identity)
        if parameters.get("IfNoneMatch") == "*" and existing is not None:
            raise client_error("PreconditionFailed", 412, "PutObject")
        if parameters.get("IfMatch") and (
            existing is None or parameters["IfMatch"] != existing["etag"]
        ):
            raise client_error("PreconditionFailed", 412, "PutObject")
        body = parameters["Body"]
        content = body.read() if hasattr(body, "read") else body
        self.put_calls.append(parameters["Key"])
        self.objects[identity] = {
            "content": content,
            "metadata": parameters["Metadata"],
            "content_type": parameters["ContentType"],
            "checksum": parameters["ChecksumSHA256"],
            "encryption": parameters["ServerSideEncryption"],
            "etag": f'"etag-{len(self.put_calls)}"',
        }
        return {}

    def head_object(self, **parameters):
        stored = self.objects[(parameters["Bucket"], parameters["Key"], None)]
        return {
            "ContentLength": len(stored["content"]),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": stored["encryption"],
        }


def processor(client):
    return CisaSilverS3Processor(
        CisaSilverLambdaConfig(
            BRONZE_BUCKET,
            SILVER_BUCKET,
            minimum_record_count=1,
            temporary_root="/tmp",
        ),
        s3_client=client,
    )


def test_processes_exact_snapshot_version_and_replay_is_idempotent():
    content = raw()
    client = MemoryS3(content)
    created = process_s3_notification(event(content), processor(client))[0]
    replay = process_s3_notification(event(content), processor(client))[0]
    assert created.created is True
    assert replay.created is False
    assert created.record_count == 2
    assert created.parquet_path.startswith(f"s3://{SILVER_BUCKET}/silver/cisa_kev_snapshots/")
    assert client.put_calls.count("silver/cisa_kev_snapshots/_latest.json") == 1


def test_rejects_non_snapshot_metadata_before_silver_write():
    content = raw()
    client = MemoryS3(content)
    bronze = next(iter(client.objects.values()))
    bronze["metadata"]["request-mode"] = "git_history"
    with pytest.raises(ValueError, match="request-mode"):
        process_s3_notification(event(content), processor(client))
    assert client.put_calls == []


def test_rejects_declared_metadata_count_mismatch():
    content = raw()
    client = MemoryS3(content)
    bronze = next(iter(client.objects.values()))
    bronze["metadata"]["record-count"] = "3"
    with pytest.raises(ValueError, match="manifest count mismatch"):
        process_s3_notification(event(content), processor(client))
    assert client.put_calls == []


def test_rejects_implausible_shrinkage_against_latest():
    content = raw(2)
    client = MemoryS3(content)
    latest = json.dumps(
        {
            "record_count": 10,
            "acquired_at": "2026-11-12T10:00:00+00:00",
            "source_sha256": "0" * 64,
        }
    ).encode()
    client.objects[(SILVER_BUCKET, "silver/cisa_kev_snapshots/_latest.json", None)] = {
        "content": latest,
        "metadata": {"dataset": "cisa_kev_snapshots"},
        "content_type": "application/json",
        "checksum": checksum(latest),
        "encryption": "AES256",
        "etag": '"latest-etag"',
    }
    with pytest.raises(ValueError, match="implausibly small"):
        process_s3_notification(event(content), processor(client))
    assert client.put_calls == []


def test_sqs_partial_failure_and_test_event(monkeypatch):
    content = raw()
    service = processor(MemoryS3(content))
    monkeypatch.setattr(
        "threatflow.transformation.cisa_silver_lambda._environment_processor",
        lambda: service,
    )
    sqs = {
        "Records": [
            {"eventSource": "aws:sqs", "messageId": "ok", "body": json.dumps(event(content))},
            {"eventSource": "aws:sqs", "messageId": "bad", "body": "invalid"},
            {
                "eventSource": "aws:sqs",
                "messageId": "test",
                "body": json.dumps(
                    {"Service": "Amazon S3", "Event": "s3:TestEvent", "Bucket": BRONZE_BUCKET}
                ),
            },
        ]
    }
    assert lambda_handler(sqs, None) == {
        "batchItemFailures": [{"itemIdentifier": "bad"}]
    }
