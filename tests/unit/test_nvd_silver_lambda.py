import base64
import json
import logging
from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO

import pytest
from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from threatflow.raw_storage import RawArtifactRef
from threatflow.transformation.nvd_silver_lambda import (
    NvdSilverLambdaConfig,
    NvdSilverS3Processor,
    lambda_handler,
    process_s3_notification,
)
from threatflow.transformation.nvd_window import (
    build_nvd_window_manifest,
    encode_nvd_window_manifest,
)

BRONZE = "bronze-test"
SILVER = "silver-test"


@pytest.fixture(autouse=True)
def enable_lambda_logger_for_capture():
    """Isolate these tests from Airflow's process-wide logging configuration."""
    logger = logging.getLogger("threatflow.transformation.nvd_silver_lambda")
    previously_disabled = logger.disabled
    logger.disabled = False
    try:
        yield
    finally:
        logger.disabled = previously_disabled


def checksum(content):
    return base64.b64encode(sha256(content).digest()).decode()


def error(code, status, operation):
    return ClientError(
        {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}, operation
    )


def page():
    return json.dumps(
        {
            "startIndex": 0,
            "resultsPerPage": 1,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "published": "2026-11-01T00:00:00Z",
                        "lastModified": "2026-11-14T00:00:00Z",
                        "descriptions": [{"lang": "en", "value": "description"}],
                        "metrics": {},
                    }
                }
            ],
        }
    ).encode()


def fixture():
    content = page()
    digest = sha256(content).hexdigest()
    key = f"bronze/source=nvd/sha256={digest}.json"
    artifact = RawArtifactRef(
        "nvd",
        digest,
        f"s3://{BRONZE}/{key}",
        "json",
        "application/json",
        len(content),
        True,
        "s3",
        BRONZE,
        key,
        "page-version",
    )
    manifest = build_nvd_window_manifest(
        mode="modified",
        requested_start=datetime(2026, 11, 13, tzinfo=UTC),
        requested_end=datetime(2026, 11, 15, tzinfo=UTC),
        acquired_at=datetime(2026, 11, 15, 3, tzinfo=UTC),
        total_results=1,
        pages=[(artifact, 0, 1)],
    )
    window = encode_nvd_window_manifest(manifest)
    window_digest = sha256(window).hexdigest()
    window_key = f"bronze/source=nvd/sha256={window_digest}.window.json"
    event = {
        "Records": [
            {
                "eventSource": "aws:s3",
                "s3": {
                    "bucket": {"name": BRONZE},
                    "object": {
                        "key": window_key.replace("=", "%3D").replace("/", "%2F"),
                        "size": len(window),
                        "versionId": "window-version",
                    },
                },
            }
        ]
    }
    return content, artifact, window, window_key, event


class MemoryS3:
    def __init__(self):
        page_content, artifact, window, window_key, _ = fixture()
        self.objects = {}
        self.put_calls = []
        self._add(
            BRONZE,
            artifact.object_key,
            artifact.version_id,
            page_content,
            {"source": "nvd", "sha256": artifact.sha256, "acquired-at": "2026-11-15T03:00:00Z"},
            "application/json",
        )
        self._add(
            BRONZE,
            window_key,
            "window-version",
            window,
            {
                "source": "nvd",
                "sha256": sha256(window).hexdigest(),
                "acquired-at": "2026-11-15T03:00:00Z",
                "artifact-kind": "window-manifest",
                "request-mode": "modified",
            },
            "application/json",
        )

    def _add(self, bucket, key, version, content, metadata, content_type):
        self.objects[(bucket, key, version)] = {
            "content": content,
            "metadata": metadata,
            "content_type": content_type,
            "checksum": checksum(content),
        }

    def get_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"], parameters.get("VersionId"))
        stored = self.objects.get(identity)
        if stored is None and parameters.get("VersionId") is None:
            stored = self.objects.get((parameters["Bucket"], parameters["Key"], None))
        if stored is None:
            raise error("NoSuchKey", 404, "GetObject")
        response = {
            "Body": StreamingBody(BytesIO(stored["content"]), len(stored["content"])),
            "ContentLength": len(stored["content"]),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": "AES256",
        }
        if parameters.get("VersionId"):
            response["VersionId"] = parameters["VersionId"]
        return response

    def put_object(self, **parameters):
        identity = (parameters["Bucket"], parameters["Key"], None)
        if parameters.get("IfNoneMatch") == "*" and identity in self.objects:
            raise error("PreconditionFailed", 412, "PutObject")
        body = parameters["Body"]
        content = body.read() if hasattr(body, "read") else body
        self.put_calls.append(parameters["Key"])
        self.objects[identity] = {
            "content": content,
            "metadata": parameters["Metadata"],
            "content_type": parameters["ContentType"],
            "checksum": parameters["ChecksumSHA256"],
        }
        return {}

    def head_object(self, **parameters):
        stored = self.objects[(parameters["Bucket"], parameters["Key"], None)]
        return {
            "ContentLength": len(stored["content"]),
            "ContentType": stored["content_type"],
            "ChecksumSHA256": stored["checksum"],
            "Metadata": stored["metadata"],
            "ServerSideEncryption": "AES256",
        }


def processor(client):
    return NvdSilverS3Processor(
        NvdSilverLambdaConfig(BRONZE, SILVER, temporary_root="/tmp"), s3_client=client
    )


def test_exact_window_and_page_versions_commit_then_reuse(caplog):
    _, _, _, _, event = fixture()
    client = MemoryS3()
    with caplog.at_level(logging.INFO):
        created = process_s3_notification(event, processor(client))[0]
        reused = process_s3_notification(event, processor(client))[0]
    assert created.created is True
    assert reused.created is False
    assert created.record_count == 1
    assert len(client.put_calls) == 2
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.message.startswith("{")
    ]
    assert [item["event"] for item in events] == [
        "bronze_received",
        "silver_committed",
        "bronze_received",
        "silver_reused",
    ]


def test_corrupt_page_fails_closed_and_emits_failure(caplog):
    _, artifact, _, _, event = fixture()
    client = MemoryS3()
    client.objects[(BRONZE, artifact.object_key, artifact.version_id)]["content"] += b"bad"
    with caplog.at_level(logging.INFO):
        with pytest.raises(ValueError, match="integrity"):
            process_s3_notification(event, processor(client))
    assert client.put_calls == []
    assert json.loads(caplog.records[-1].message)["event"] == "processing_failed"


def test_sqs_partial_failure(monkeypatch):
    _, _, _, _, event = fixture()
    monkeypatch.setattr(
        "threatflow.transformation.nvd_silver_lambda._environment_processor",
        lambda: processor(MemoryS3()),
    )
    response = lambda_handler(
        {
            "Records": [
                {"eventSource": "aws:sqs", "messageId": "ok", "body": json.dumps(event)},
                {"eventSource": "aws:sqs", "messageId": "bad", "body": "bad-json"},
            ]
        },
        None,
    )
    assert response == {"batchItemFailures": [{"itemIdentifier": "bad"}]}
