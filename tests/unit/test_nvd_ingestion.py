import json
import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from threatflow.config import Settings
from threatflow.ingestion import nvd_client, nvd_ingestion
from threatflow.ingestion.nvd_parser import parse_response
from threatflow.raw_storage import RawArtifactRef


def payload(start=0, total=1, records=None):
    return json.dumps(
        {
            "startIndex": start,
            "resultsPerPage": len(records or []),
            "totalResults": total,
            "vulnerabilities": records or [],
        }
    ).encode()


def cve(id="CVE-2024-1234", modified="2024-01-02T00:00:00.000Z", metrics=None):
    return {
        "cve": {
            "id": id,
            "published": "2024-01-01T00:00:00.000Z",
            "lastModified": modified,
            "descriptions": [{"lang": "en", "value": "description"}],
            "metrics": metrics or {},
        }
    }


def test_parser_allows_optional_metrics_and_projects_fields():
    _, rows = parse_response(payload(records=[cve()]))
    assert rows[0]["cvss_score"] is None
    assert rows[0]["cwe_ids"] is None
    assert rows[0]["references"] is None


def test_logs_response_fields_and_accepted_schema_drift(caplog, monkeypatch):
    monkeypatch.setattr(
        logging.getLogger("threatflow.ingestion.nvd_parser"), "disabled", False
    )
    record = cve()
    record["cve"]["newSourceField"] = "value"
    value = json.loads(payload(records=[record]))
    value["newResponseField"] = "value"

    with caplog.at_level(logging.INFO):
        _, rows = parse_response(json.dumps(value).encode())

    assert len(rows) == 1
    assert "source=nvd scope=response status=accepted_with_drift" in caplog.text
    assert "unexpected_fields=newResponseField" in caplog.text
    assert "source=nvd scope=cve status=accepted_with_drift" in caplog.text
    assert "unexpected_fields=newSourceField" in caplog.text


def test_parser_treats_nvd_offsetless_response_timestamps_as_utc():
    record = cve(modified="2024-01-02T00:00:00.000")
    record["cve"]["published"] = "2024-01-01T00:00:00.000"

    _, rows = parse_response(payload(records=[record]))

    assert rows[0]["published"] == datetime(2024, 1, 1, tzinfo=UTC)
    assert rows[0]["last_modified"] == datetime(2024, 1, 2, tzinfo=UTC)


def test_cvss_version_and_primary_metric_selection():
    metrics = {
        "cvssMetricV31": [
            {"type": "PRIMARY", "cvssData": {"baseScore": 9.8, "vectorString": "high"}},
            {"type": "SECONDARY", "cvssData": {"baseScore": 4.0, "vectorString": "low"}},
        ]
    }
    _, rows = parse_response(payload(records=[cve(metrics=metrics)]))
    assert (rows[0]["cvss_version"], rows[0]["cvss_score"]) == ("3.1", 9.8)


def test_parser_rejects_invalid_id_and_required_fields():
    with pytest.raises(ValueError, match="identifier"):
        parse_response(payload(records=[cve("bad")]))
    value = json.loads(payload(records=[cve()]))
    del value["vulnerabilities"][0]["cve"]["published"]
    with pytest.raises(ValueError, match="published"):
        parse_response(json.dumps(value).encode())


def test_client_window_limits_and_api_key_header(monkeypatch):
    seen = {}

    class Response:
        content = b"{}"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(nvd_client.httpx, "get", lambda *a, **kw: seen.update(kw) or Response())
    client = nvd_client.NvdClient(
        base_url="https://example", api_key="secret", min_interval=0, sleep=lambda _: None
    )
    start = datetime.now(UTC) - timedelta(hours=1)
    client.fetch_page(start, datetime.now(UTC), 0)
    assert seen["headers"]["apiKey"] == "secret"
    assert "lastModStartDate" in seen["params"] and "lastModEndDate" in seen["params"]
    with pytest.raises(ValueError):
        client.fetch_page(start - timedelta(days=121), datetime.now(UTC), 0)


def test_pagination_and_duplicate_resolution():
    r1, r2 = cve(modified="2024-01-02T00:00:00.000Z"), cve(modified="2024-01-03T00:00:00.000Z")

    class Client:
        def __init__(self):
            self.calls = []

        def fetch_page(self, start, end, index):
            self.calls.append(index)
            return payload(index, 2, [r1] if index == 0 else [r2])

    class S3Store:
        backend = "s3"

        def __init__(self):
            self.stored = []

        def store(
            self, source, content, acquired_at, extension, *, content_type=None, metadata=None
        ):
            self.stored.append((source, content, extension, metadata))
            digest = sha256(content).hexdigest()
            return RawArtifactRef(
                source=source,
                sha256=digest,
                uri=f"s3://bronze/bronze/source={source}/sha256={digest}.{extension.lstrip('.')}",
                extension=extension.lstrip("."),
                content_type=content_type,
                size_bytes=len(content),
                created=True,
                backend="s3",
                bucket="bronze",
                object_key=f"bronze/source={source}/sha256={digest}.{extension.lstrip('.')}",
                version_id=f"version-{digest[:12]}",
                first_acquired_at=acquired_at,
            )

    store = S3Store()
    settings = Settings(
        raw_storage_backend="s3",
        s3_bronze_bucket="bronze",
        nvd_page_size=1,
        _env_file=None,
    )
    result = nvd_ingestion.ingest_nvd_cves(
        client=Client(),
        settings=settings,
        start=datetime(2024, 1, 1, tzinfo=UTC),
        end=datetime(2024, 1, 5, tzinfo=UTC),
        raw_store=store,
    )
    assert result.pages_retrieved == 2 and result.total_records_received == 2
    assert result.unique_records_processed == 1
    assert result.rejected_count == 0
    assert result.window_manifest_uri is not None
    assert result.window_manifest_version_id is not None
    assert len(store.stored) == 3
    assert store.stored[-1][2] == ".window.json"


def test_identical_retry_reuses_nvd_window_manifest(monkeypatch):
    first_acquisition = datetime(2026, 11, 20, 3, tzinfo=UTC)
    retry_acquisition = first_acquisition + timedelta(minutes=5)

    class Clock(datetime):
        values = iter((first_acquisition, retry_acquisition))

        @classmethod
        def now(cls, tz=None):
            value = next(cls.values)
            return value if tz is None else value.astimezone(tz)

    class Client:
        def fetch_page(self, start, end, index):
            assert index == 0
            return payload(0, 1, [cve()])

    class ContentAddressedStore:
        backend = "s3"

        def __init__(self):
            self.artifacts = {}

        def store(
            self, source, content, acquired_at, extension, *, content_type=None, metadata=None
        ):
            del metadata
            normalized_extension = extension.removeprefix(".")
            digest = sha256(content).hexdigest()
            identity = source, digest, normalized_extension
            existing = self.artifacts.get(identity)
            if existing is not None:
                return replace(existing, created=False)
            artifact = RawArtifactRef(
                source=source,
                sha256=digest,
                uri=(
                    f"s3://bronze/bronze/source={source}/"
                    f"sha256={digest}.{normalized_extension}"
                ),
                extension=normalized_extension,
                content_type=content_type or "application/json",
                size_bytes=len(content),
                created=True,
                backend="s3",
                bucket="bronze",
                object_key=(
                    f"bronze/source={source}/sha256={digest}.{normalized_extension}"
                ),
                version_id=f"version-{digest[:12]}",
                first_acquired_at=acquired_at,
            )
            self.artifacts[identity] = artifact
            return artifact

    monkeypatch.setattr(nvd_ingestion, "datetime", Clock)
    store = ContentAddressedStore()
    settings = Settings(
        raw_storage_backend="s3",
        s3_bronze_bucket="bronze",
        _env_file=None,
    )
    start = datetime(2026, 11, 19, tzinfo=UTC)
    end = datetime(2026, 11, 20, tzinfo=UTC)

    first = nvd_ingestion.ingest_nvd_cves(
        client=Client(), settings=settings, start=start, end=end, raw_store=store
    )
    retry = nvd_ingestion.ingest_nvd_cves(
        client=Client(), settings=settings, start=start, end=end, raw_store=store
    )

    assert retry.window_manifest_sha256 == first.window_manifest_sha256
    assert first.bronze_objects_created == 2
    assert retry.bronze_objects_created == 0
    assert retry.bronze_objects_reused == 2


def test_total_change_fails_without_publishing_window_manifest():
    class Client:
        def fetch_page(self, start, end, index):
            return payload(index, 2 if index == 0 else 3, [cve(id=f"CVE-2024-{index + 1:04d}")])

    settings = Settings(
        raw_storage_backend="s3",
        s3_bronze_bucket="bronze",
        nvd_page_size=1,
        _env_file=None,
    )

    class RecordingStore:
        backend = "s3"

        def __init__(self):
            self.extensions = []

        def store(self, source, content, acquired_at, extension, **kwargs):
            self.extensions.append(extension)
            digest = sha256(content).hexdigest()
            return RawArtifactRef(
                source,
                digest,
                f"s3://bronze/bronze/source={source}/{digest}.json",
                extension.removeprefix("."),
                "application/json",
                len(content),
                True,
                "s3",
                "bronze",
                f"bronze/source={source}/{digest}.json",
                f"version-{digest[:12]}",
            )

    store = RecordingStore()
    quarantine = RecordingStore()

    with pytest.raises(ValueError, match="totalResults changed"):
        nvd_ingestion.ingest_nvd_cves(
            client=Client(),
            settings=settings,
            start=datetime(2024, 1, 1, tzinfo=UTC),
            end=datetime(2024, 1, 5, tzinfo=UTC),
            raw_store=store,
            quarantine_store=quarantine,
        )
    assert store.extensions == [".json"]
    assert quarantine.extensions == [".json"]
