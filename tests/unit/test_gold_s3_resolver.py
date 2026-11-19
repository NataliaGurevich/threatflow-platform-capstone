import base64
import hashlib
import io
import json
from datetime import UTC, date, datetime

import pytest
from botocore.exceptions import ClientError

from threatflow.gold.s3_resolver import S3GoldInputError, S3SilverResolver


class Body(io.BytesIO):
    pass


class Paginator:
    def __init__(self, objects):
        self.objects = objects

    def paginate(self, *, Bucket, Prefix):
        del Bucket
        yield {
            "Contents": [
                {"Key": key} for key in sorted(self.objects) if key.startswith(Prefix)
            ]
        }


class FakeS3:
    def __init__(self, objects, *, expose_sha256=True):
        self.objects = objects
        self.expose_sha256 = expose_sha256

    def get_object(self, *, Bucket, Key):
        del Bucket
        if Key not in self.objects:
            raise ClientError(
                {
                    "Error": {"Code": "NoSuchKey", "Message": "missing"},
                    "ResponseMetadata": {"HTTPStatusCode": 404},
                },
                "GetObject",
            )
        return {"Body": Body(self.objects[Key])}

    def head_object(self, *, Bucket, Key, ChecksumMode):
        del Bucket
        assert ChecksumMode == "ENABLED"
        content = self.objects[Key]
        response = {
            "ContentLength": len(content),
            "Metadata": {},
        }
        if self.expose_sha256:
            response["ChecksumSHA256"] = base64.b64encode(bytes.fromhex("a" * 64)).decode()
        return response

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return Paginator(self.objects)


def manifest(dataset, parquet_file, **values):
    payload = {
        "dataset": dataset,
        "schema_version": 1,
        "transform_version": "1.0.0",
        "record_count": 10,
        "parquet": {
            "file": parquet_file,
            "sha256": "a" * 64,
            "size_bytes": 4,
        },
        **values,
    }
    return json.dumps(payload).encode()


def silver_objects():
    objects = {}

    def add(partition, payload, filename):
        objects[f"silver/{partition}/_manifest.json"] = payload
        objects[f"silver/{partition}/{filename}"] = b"data"

    add(
        "epss_scores/score_date=2026-11-13",
        manifest("epss_scores", "epss.parquet", score_date="2026-11-13"),
        "epss.parquet",
    )
    add(
        "epss_scores/score_date=2026-11-06",
        manifest("epss_scores", "epss.parquet", score_date="2026-11-06"),
        "epss.parquet",
    )
    for kind, observed, identity in (
        ("snapshot", "2026-11-10T04:00:00Z", "current"),
        ("git_history", "2026-11-12T04:00:00Z", "history"),
    ):
        add(
            f"cisa_kev_snapshots/snapshot_kind={kind}/snapshot_id={identity}",
            manifest(
                "cisa_kev_snapshots",
                "cisa_kev.parquet",
                snapshot={"kind": kind, "observed_at": observed, "id": identity},
            ),
            "cisa_kev.parquet",
        )
    for mode, window_end, identity in (
        ("published", "2020-12-31T23:59:59Z", "published"),
        ("modified", "2026-11-12T23:59:59Z", "modified"),
        ("modified", "2026-11-14T23:59:59Z", "future"),
    ):
        add(
            f"nvd_cve_windows/mode={mode}/window_end={identity}/window_id={identity}",
            manifest(
                "nvd_cve_windows",
                "nvd_cves.parquet",
                mode=mode,
                window_start="2020-01-01T00:00:00Z",
                window_end=window_end,
                window_id=identity,
            ),
            "nvd_cves.parquet",
        )
    return objects


def test_resolves_observed_inputs_and_excludes_future_nvd() -> None:
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(silver_objects()))
    plan = resolver.resolve(
        date(2026, 11, 13),
        source_cutoff=datetime(2026, 11, 13, 23, 59, tzinfo=UTC),
        snapshot_type="OBSERVED",
        nvd_history_complete=True,
    )

    assert plan.epss_current.manifest["score_date"] == "2026-11-13"
    assert plan.epss_previous.manifest["score_date"] == "2026-11-06"
    assert plan.cisa.manifest["snapshot"]["kind"] == "snapshot"
    assert [item.manifest["window_id"] for item in plan.nvd] == [
        "published",
        "modified",
    ]


def test_reconstructed_selects_git_history() -> None:
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(silver_objects()))
    plan = resolver.resolve(
        date(2026, 11, 13),
        source_cutoff=datetime(2026, 11, 13, 23, 59, tzinfo=UTC),
        snapshot_type="RECONSTRUCTED",
        nvd_history_complete=False,
    )
    assert plan.cisa.manifest["snapshot"]["kind"] == "git_history"
    assert plan.fingerprint_plan()["nvd"]["history_complete"] is False


def test_falls_back_to_streamed_sha256_for_legacy_silver_objects() -> None:
    objects = silver_objects()
    actual_sha256 = hashlib.sha256(b"data").hexdigest()
    for key, content in list(objects.items()):
        if key.endswith("/_manifest.json"):
            payload = json.loads(content)
            payload["parquet"]["sha256"] = actual_sha256
            objects[key] = json.dumps(payload).encode()
    resolver = S3SilverResolver(
        "bucket", s3_client=FakeS3(objects, expose_sha256=False)
    )
    plan = resolver.resolve(
        date(2026, 11, 13),
        source_cutoff=datetime(2026, 11, 13, 23, 59, tzinfo=UTC),
        snapshot_type="RECONSTRUCTED",
        nvd_history_complete=False,
    )
    assert plan.epss_previous.manifest["score_date"] == "2026-11-06"


def test_missing_previous_epss_fails_before_spark() -> None:
    objects = silver_objects()
    prefix = "silver/epss_scores/score_date=2026-11-06/"
    objects = {key: value for key, value in objects.items() if not key.startswith(prefix)}
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(objects))

    with pytest.raises(S3GoldInputError, match="missing committed Silver manifest"):
        resolver.resolve(
            date(2026, 11, 13),
            source_cutoff=datetime(2026, 11, 13, 23, 59, tzinfo=UTC),
            snapshot_type="RECONSTRUCTED",
            nvd_history_complete=False,
        )


def test_auto_selects_latest_ready_epss_pair() -> None:
    objects = silver_objects()
    objects[
        "silver/epss_scores/score_date=2026-11-14/_manifest.json"
    ] = manifest("epss_scores", "epss.parquet", score_date="2026-11-14")
    objects["silver/epss_scores/score_date=2026-11-14/epss.parquet"] = b"data"
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(objects))

    selected = resolver.select_latest_ready_snapshot_date(
        latest_allowed_date=date(2026, 11, 14),
        max_input_lag_days=2,
    )

    assert selected == date(2026, 11, 13)


def test_auto_rejects_stale_latest_ready_epss_pair() -> None:
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(silver_objects()))

    with pytest.raises(S3GoldInputError, match="maximum is 2"):
        resolver.select_latest_ready_snapshot_date(
            latest_allowed_date=date(2026, 11, 19),
            max_input_lag_days=2,
        )


def test_auto_fails_without_complete_epss_pair() -> None:
    objects = silver_objects()
    previous_prefix = "silver/epss_scores/score_date=2026-11-06/"
    objects = {
        key: value for key, value in objects.items() if not key.startswith(previous_prefix)
    }
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(objects))

    with pytest.raises(S3GoldInputError, match="no ready EPSS snapshot"):
        resolver.select_latest_ready_snapshot_date(
            latest_allowed_date=date(2026, 11, 14),
            max_input_lag_days=2,
        )


def test_rejects_observed_at_after_cutoff() -> None:
    objects = silver_objects()
    for key in list(objects):
        if "snapshot_kind=snapshot" in key:
            del objects[key]
    resolver = S3SilverResolver("bucket", s3_client=FakeS3(objects))
    with pytest.raises(S3GoldInputError, match="no committed CISA snapshot"):
        resolver.resolve(
            date(2026, 11, 13),
            source_cutoff=datetime(2026, 11, 13, 23, 59, tzinfo=UTC),
            snapshot_type="OBSERVED",
            nvd_history_complete=True,
        )
