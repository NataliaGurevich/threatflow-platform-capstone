from datetime import UTC, datetime
from hashlib import sha256
from io import BytesIO

from botocore.exceptions import ClientError
from botocore.response import StreamingBody

from threatflow.raw_storage import RawArtifactRef
from threatflow.transformation import nvd_silver_reconciliation
from threatflow.transformation.nvd_silver_reconciliation import reconcile_nvd_silver
from threatflow.transformation.nvd_window import (
    build_nvd_window_manifest,
    encode_nvd_window_manifest,
)


def client_error():
    return ClientError(
        {"Error": {"Code": "NotFound"}, "ResponseMetadata": {"HTTPStatusCode": 404}},
        "HeadObject",
    )


def window():
    page = b"page"
    digest = sha256(page).hexdigest()
    artifact = RawArtifactRef(
        "nvd", digest, "s3://bronze/page", "json", "application/json", len(page), True,
        "s3", "bronze", f"bronze/source=nvd/sha256={digest}.json", "page-version",
    )
    manifest = build_nvd_window_manifest(
        mode="modified",
        requested_start=datetime(2026, 11, 13, tzinfo=UTC),
        requested_end=datetime(2026, 11, 15, tzinfo=UTC),
        acquired_at=datetime(2026, 11, 15, 3, tzinfo=UTC),
        total_results=1,
        pages=[(artifact, 0, 1)],
    )
    return encode_nvd_window_manifest(manifest)


class Paginator:
    def __init__(self, content):
        self.content = content

    def paginate(self, **kwargs):
        del kwargs
        digest = sha256(self.content).hexdigest()
        return [{"Versions": [{
            "Key": f"bronze/source=nvd/sha256={digest}.window.json",
            "VersionId": "window-version", "Size": len(self.content), "IsLatest": True,
        }]}]


class S3:
    def __init__(self, committed=False):
        self.content = window()
        self.committed = committed

    def get_paginator(self, name):
        assert name == "list_object_versions"
        return Paginator(self.content)

    def get_object(self, **kwargs):
        del kwargs
        return {"Body": StreamingBody(BytesIO(self.content), len(self.content))}

    def head_object(self, **kwargs):
        del kwargs
        if not self.committed:
            raise client_error()
        return {}


class Sqs:
    def __init__(self):
        self.messages = []

    def send_message(self, **kwargs):
        self.messages.append(kwargs)


def test_dry_run_reports_missing_without_sqs_write():
    result = reconcile_nvd_silver(
        bronze_bucket="bronze", silver_bucket="silver", apply=False, s3_client=S3()
    )
    assert result[0].status == "missing"


def test_apply_enqueues_only_missing_exact_window():
    sqs = Sqs()
    result = reconcile_nvd_silver(
        bronze_bucket="bronze", silver_bucket="silver", queue_url="queue", apply=True,
        s3_client=S3(), sqs_client=sqs,
    )
    assert result[0].status == "enqueued"
    assert len(sqs.messages) == 1
    assert "window-version" in sqs.messages[0]["MessageBody"]


def test_committed_window_is_not_reenqueued():
    sqs = Sqs()
    result = reconcile_nvd_silver(
        bronze_bucket="bronze", silver_bucket="silver", queue_url="queue", apply=True,
        s3_client=S3(committed=True), sqs_client=sqs,
    )
    assert result[0].status == "committed"
    assert sqs.messages == []


def test_cli_region_configures_the_whole_boto3_session(monkeypatch, capsys):
    observed = {}
    s3 = S3(committed=True)

    class Session:
        def __init__(self, *, region_name):
            observed["region_name"] = region_name

        def client(self, service_name):
            observed.setdefault("services", []).append(service_name)
            return s3

    monkeypatch.setattr(nvd_silver_reconciliation.boto3, "Session", Session)
    monkeypatch.setattr(
        "sys.argv",
        [
            "threatflow-reconcile-nvd-silver",
            "--dry-run",
            "--bronze-bucket",
            "bronze",
            "--silver-bucket",
            "silver",
            "--region",
            "eu-central-1",
        ],
    )

    nvd_silver_reconciliation.main()

    assert observed == {"region_name": "eu-central-1", "services": ["s3"]}
    assert '"status": "committed"' in capsys.readouterr().out
