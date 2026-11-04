import json
from datetime import UTC, datetime, timedelta

import pytest

from threatflow.config import Settings
from threatflow.ingestion import nvd_client, nvd_ingestion
from threatflow.ingestion.nvd_parser import parse_response


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


def test_pagination_and_duplicate_resolution(monkeypatch, tmp_path):
    r1, r2 = cve(modified="2024-01-02T00:00:00.000Z"), cve(modified="2024-01-03T00:00:00.000Z")

    class Client:
        def __init__(self):
            self.calls = []

        def fetch_page(self, start, end, index):
            self.calls.append(index)
            return payload(index, 2, [r1] if index == 0 else [r2])

    class Result:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def flush(self):
            pass

    class Engine:
        def begin(self):
            return Result()

        def dispose(self):
            pass

    monkeypatch.setattr(nvd_ingestion, "create_engine", lambda _: Engine())
    monkeypatch.setattr(nvd_ingestion, "upsert_records", lambda session, rows: (1, 0))
    settings = Settings(raw_data_dir=str(tmp_path), nvd_page_size=1)
    result = nvd_ingestion.ingest_nvd_cves(
        client=Client(),
        settings=settings,
        start=datetime(2024, 1, 1, tzinfo=UTC),
        end=datetime(2024, 1, 5, tzinfo=UTC),
    )
    assert result.pages_retrieved == 2 and result.total_records_received == 2
    assert result.unique_records_processed == 1
    assert result.rejected_count == 0


def test_total_change_fails_after_raw_storage(monkeypatch, tmp_path):
    class Client:
        def fetch_page(self, start, end, index):
            return payload(index, 2 if index == 0 else 3, [cve(id=f"CVE-2024-{index + 1:04d}")])

    settings = Settings(raw_data_dir=str(tmp_path), nvd_page_size=1)
    with pytest.raises(ValueError, match="totalResults changed"):
        nvd_ingestion.ingest_nvd_cves(
            client=Client(),
            settings=settings,
            start=datetime(2024, 1, 1, tzinfo=UTC),
            end=datetime(2024, 1, 5, tzinfo=UTC),
        )
