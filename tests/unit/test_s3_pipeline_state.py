import base64
import hashlib
import json
from datetime import UTC, date, datetime
from io import BytesIO

import pytest
from botocore.exceptions import ClientError

from threatflow.s3_pipeline_state import S3PipelineState


class Body(BytesIO):
    pass


class FakeS3:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.puts = []

    def get_object(self, *, Bucket, Key, ChecksumMode):
        assert ChecksumMode == "ENABLED"
        value = self.objects.get((Bucket, Key))
        if value is None:
            raise ClientError(
                {
                    "Error": {"Code": "NoSuchKey", "Message": "missing"},
                    "ResponseMetadata": {"HTTPStatusCode": 404},
                },
                "GetObject",
            )
        encoded, etag = value
        digest = hashlib.sha256(encoded).digest()
        return {
            "Body": Body(encoded),
            "ChecksumSHA256": base64.b64encode(digest).decode(),
            "Metadata": {"sha256": hashlib.sha256(encoded).hexdigest()},
            "ETag": etag,
        }

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        return {"ETag": '"new"'}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def state(client):
    return S3PipelineState(
        bronze_bucket="bronze-bucket",
        silver_bucket="silver-bucket",
        client=client,
    )


def test_first_nvd_checkpoint_write_is_conditional_and_utc():
    client = FakeS3()
    covered_until = datetime(2026, 11, 24, 3, tzinfo=UTC)

    assert state(client).nvd_covered_until() is None
    state(client).advance_nvd_covered_until(covered_until)

    put = client.puts[0]
    assert put["IfNoneMatch"] == "*"
    assert "IfMatch" not in put
    assert put["Key"] == "bronze/_control/nvd/modified-checkpoint.json"
    assert json.loads(put["Body"])["covered_until"] == covered_until.isoformat()


def test_nvd_checkpoint_update_uses_etag_and_never_regresses():
    key = ("bronze-bucket", "bronze/_control/nvd/modified-checkpoint.json")
    current = encoded(
        {
            "schema_version": 1,
            "source": "nvd",
            "mode": "modified",
            "covered_until": "2026-11-24T03:00:00+00:00",
        }
    )
    client = FakeS3({key: (current, '"current"')})
    pipeline_state = state(client)

    pipeline_state.advance_nvd_covered_until(datetime(2026, 11, 25, 3, tzinfo=UTC))
    assert client.puts[0]["IfMatch"] == '"current"'

    pipeline_state.advance_nvd_covered_until(datetime(2026, 11, 23, 3, tzinfo=UTC))
    assert len(client.puts) == 1


def test_reads_committed_silver_counts_for_bronze_quality_gates():
    cisa_key = ("silver-bucket", "silver/cisa_kev_snapshots/_latest.json")
    epss_key = (
        "silver-bucket",
        "silver/epss_scores/score_date=2026-11-23/_manifest.json",
    )
    client = FakeS3(
        {
            cisa_key: (
                encoded({"dataset": "cisa_kev_snapshots", "record_count": 1_250}),
                '"cisa"',
            ),
            epss_key: (
                encoded(
                    {
                        "dataset": "epss_scores",
                        "score_date": "2026-11-23",
                        "record_count": 295_000,
                    }
                ),
                '"epss"',
            ),
        }
    )
    pipeline_state = state(client)

    assert pipeline_state.latest_cisa_record_count() == 1_250
    assert pipeline_state.epss_record_count(date(2026, 11, 23)) == 295_000
    assert pipeline_state.epss_record_count(date(2026, 11, 22)) is None


def test_rejects_corrupt_state_checksum():
    key = ("bronze-bucket", "bronze/_control/nvd/modified-checkpoint.json")
    content = encoded(
        {
            "source": "nvd",
            "mode": "modified",
            "covered_until": "2026-11-24T03:00:00+00:00",
        }
    )

    class CorruptS3(FakeS3):
        def get_object(self, **kwargs):
            response = super().get_object(**kwargs)
            response["ChecksumSHA256"] = base64.b64encode(b"wrong").decode()
            return response

    with pytest.raises(ValueError, match="checksum"):
        state(CorruptS3({key: (content, '"etag"')})).nvd_covered_until()
