import base64
import gzip
import json
from hashlib import sha256
from io import BytesIO
from pathlib import Path

import pyarrow.parquet as pq
import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from threatflow.transformation import epss_silver
from threatflow.transformation.epss_silver_lambda import (
    EpssSilverLambdaConfig,
    EpssSilverS3Processor,
    lambda_handler,
    process_s3_notification,
)

BRONZE_BUCKET = "threatflow-bronze-test"
SILVER_BUCKET = "threatflow-silver-test"
VERSION_ID = "bronze-version-1"
FIXTURE_PATH = Path("tests/fixtures/aws/s3_epss_object_created.json")


def raw() -> bytes:
    return gzip.compress(
        (
            b"#model_version:v2025.03.14,score_date:2026-11-11T00:00:00Z\n"
            b"cve,epss,percentile\n"
            b"CVE-2026-0001,0.1,0.2\n"
            b"CVE-2026-0002,0.3,0.4\n"
        ),
        mtime=0,
    )


def load_event() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


class MemoryS3:
    def __init__(self, content: bytes) -> None:
        self.objects: dict[tuple[str, str, str | None], dict] = {}
        self.put_calls: list[tuple[str, str]] = []
        self.get_calls: list[dict] = []
        self.fail_manifest_once = False
        event = load_event()["Records"][0]["s3"]["object"]
        key = event["key"].replace("%2F", "/").replace("%3D", "=")
        digest = sha256(content).hexdigest()
        self.objects[(BRONZE_BUCKET, key, VERSION_ID)] = {
            "content": content,
            "metadata": {
                "sha256": digest,
                "source": "epss",
                "acquired-at": "2026-11-12T06:00:00+00:00",
            },
            "content_type": "application/gzip",
            "checksum": _checksum(content),
            "encryption": "AES256",
        }

    def get_object(self, **parameters):
        self.get_calls.append(parameters)
        bucket = parameters["Bucket"]
        key = parameters["Key"]
        version_id = parameters.get("VersionId")
        stored = self.objects.get((bucket, key, version_id))
        if stored is None and version_id is None:
            stored = self.objects.get((bucket, key, None))
        if stored is None:
            raise _client_error("NoSuchKey", 404, "GetObject")
        content = stored["content"]
        response = {
            "Body": StreamingBody(BytesIO(content), len(content)),
            "ContentLength": len(content),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": stored["encryption"],
        }
        if version_id is not None:
            response["VersionId"] = version_id
        return response

    def put_object(self, **parameters):
        bucket = parameters["Bucket"]
        key = parameters["Key"]
        self.put_calls.append((bucket, key))
        if self.fail_manifest_once and key.endswith("/_manifest.json"):
            self.fail_manifest_once = False
            raise _client_error("InternalError", 500, "PutObject")
        identity = (bucket, key, None)
        if parameters.get("IfNoneMatch") == "*" and identity in self.objects:
            raise _client_error("PreconditionFailed", 412, "PutObject")
        body = parameters["Body"]
        content = body.read() if hasattr(body, "read") else body
        self.objects[identity] = {
            "content": content,
            "metadata": parameters["Metadata"],
            "content_type": parameters["ContentType"],
            "checksum": parameters["ChecksumSHA256"],
            "encryption": parameters["ServerSideEncryption"],
        }
        return {}

    def head_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"], parameters.get("VersionId"))
        stored = self.objects.get(identity)
        if stored is None:
            raise _client_error("NotFound", 404, "HeadObject")
        return {
            "ContentLength": len(stored["content"]),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": stored["encryption"],
        }


def processor(client: MemoryS3) -> EpssSilverS3Processor:
    return EpssSilverS3Processor(
        EpssSilverLambdaConfig(
            bronze_bucket=BRONZE_BUCKET,
            silver_bucket=SILVER_BUCKET,
            temporary_root="/tmp",
        ),
        s3_client=client,
    )


def test_fixture_processes_exact_bronze_version_and_reuses_committed_partition(
    monkeypatch,
) -> None:
    content = raw()
    assert len(content) == 116
    assert sha256(content).hexdigest() in load_event()["Records"][0]["s3"]["object"]["key"]
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    client = MemoryS3(content)
    service = processor(client)

    created = process_s3_notification(load_event(), service)[0]
    reused = process_s3_notification(load_event(), service)[0]

    assert created.created is True
    assert reused.created is False
    assert created.parquet_path == (
        "s3://threatflow-silver-test/"
        "silver/epss_scores/score_date=2026-11-11/epss.parquet"
    )
    assert client.get_calls[0]["VersionId"] == VERSION_ID
    assert len(client.put_calls) == 2
    parquet = client.objects[(
        SILVER_BUCKET,
        "silver/epss_scores/score_date=2026-11-11/epss.parquet",
        None,
    )]["content"]
    assert pq.read_table(BytesIO(parquet)).num_rows == 2
    manifest = json.loads(
        client.objects[(
            SILVER_BUCKET,
            "silver/epss_scores/score_date=2026-11-11/_manifest.json",
            None,
        )]["content"]
    )
    assert manifest["source"]["version_id"] == VERSION_ID
    assert manifest["record_count"] == 2


def test_retry_recovers_when_parquet_exists_without_commit_manifest(monkeypatch) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    client = MemoryS3(raw())
    client.fail_manifest_once = True
    service = processor(client)

    with pytest.raises(ClientError, match="InternalError"):
        process_s3_notification(load_event(), service)

    result = process_s3_notification(load_event(), service)[0]
    assert result.created is True
    assert client.put_calls.count(
        (SILVER_BUCKET, "silver/epss_scores/score_date=2026-11-11/epss.parquet")
    ) == 2


def test_bronze_checksum_mismatch_never_writes_silver(monkeypatch) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    client = MemoryS3(raw() + b"corrupt")

    with pytest.raises(ValueError, match="integrity verification"):
        process_s3_notification(load_event(), processor(client))

    assert client.put_calls == []


def test_event_requires_version_id() -> None:
    event = load_event()
    del event["Records"][0]["s3"]["object"]["versionId"]

    with pytest.raises(ValueError, match="missing bucket, key, versionId, or size"):
        process_s3_notification(event, processor(MemoryS3(raw())))


def test_sqs_wrapper_reports_only_failed_messages(monkeypatch) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    service = processor(MemoryS3(raw()))
    monkeypatch.setattr(
        "threatflow.transformation.epss_silver_lambda._environment_processor",
        lambda: service,
    )
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "messageId": "ok-message",
                "body": json.dumps(load_event()),
            },
            {
                "eventSource": "aws:sqs",
                "messageId": "bad-message",
                "body": "not-json",
            },
        ]
    }

    response = lambda_handler(event, None)

    assert response == {"batchItemFailures": [{"itemIdentifier": "bad-message"}]}


def test_sqs_wrapper_acknowledges_expected_s3_destination_test_event(monkeypatch) -> None:
    client = MemoryS3(raw())
    service = processor(client)
    monkeypatch.setattr(
        "threatflow.transformation.epss_silver_lambda._environment_processor",
        lambda: service,
    )
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "messageId": "s3-test-message",
                "body": json.dumps(
                    {
                        "Service": "Amazon S3",
                        "Event": "s3:TestEvent",
                        "Bucket": BRONZE_BUCKET,
                        "RequestId": "test-request",
                        "HostId": "test-host",
                    }
                ),
            }
        ]
    }

    response = lambda_handler(event, None)

    assert response == {"batchItemFailures": []}
    assert client.get_calls == []
    assert client.put_calls == []


def test_sqs_wrapper_rejects_s3_test_event_for_another_bucket(monkeypatch) -> None:
    service = processor(MemoryS3(raw()))
    monkeypatch.setattr(
        "threatflow.transformation.epss_silver_lambda._environment_processor",
        lambda: service,
    )
    event = {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "messageId": "wrong-bucket-test-message",
                "body": json.dumps(
                    {
                        "Service": "Amazon S3",
                        "Event": "s3:TestEvent",
                        "Bucket": "unexpected-bronze-bucket",
                    }
                ),
            }
        ]
    }

    response = lambda_handler(event, None)

    assert response == {
        "batchItemFailures": [{"itemIdentifier": "wrong-bucket-test-message"}]
    }


def _checksum(content: bytes) -> str:
    return base64.b64encode(sha256(content).digest()).decode("ascii")


def _client_error(code: str, status: int, operation: str) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": code},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        operation,
    )
