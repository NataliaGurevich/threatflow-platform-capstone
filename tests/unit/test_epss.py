import gzip
import logging
from datetime import date
from types import SimpleNamespace

import pytest

from threatflow.ingestion.epss_client import ARCHIVE_URL, EpssArchiveNotFound, EpssClient
from threatflow.ingestion.epss_parser import parse_dataset
from threatflow.raw_storage import store_raw_artifact


def gz(text):
    return gzip.compress(text.encode())


def test_historical_url_and_date_validation(monkeypatch):
    seen = []

    class Response:
        content = gz("cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n")

        def raise_for_status(self):
            pass

    monkeypatch.setattr(
        "threatflow.ingestion.epss_client.httpx.get",
        lambda url, **kw: seen.append(url) or Response(),
    )
    assert EpssClient().fetch(date(2024, 12, 21)) == Response.content
    assert seen[0] == ARCHIVE_URL.format(year=2024, date="2024-12-21")
    with pytest.raises(ValueError):
        EpssClient().fetch(date(2020, 1, 1))


def test_parse_validation_and_exact_raw_bytes(tmp_path):
    raw = gz(
        "#model_version:v1,score_date:2024-01-01T00:00:00Z\ncve,epss,percentile\nCVE-2024-1234,0.1,0.2\n"
    )
    rows = parse_dataset(raw, date(2024, 1, 1))
    assert rows[0]["epss_score"] == 0.1
    stored = store_raw_artifact(
        "epss", raw, __import__("datetime").datetime.now(), ".csv.gz", raw_data_dir=tmp_path
    )
    assert stored.path.read_bytes() == raw


def test_legacy_dataset_derives_percentiles_with_equal_scores_tied():
    rows = parse_dataset(
        gz("cve,epss\nCVE-2021-0001,0.1\nCVE-2021-0002,0.2\nCVE-2021-0003,0.2\n"),
        date(2021, 4, 14),
    )

    assert [row["percentile"] for row in rows] == [pytest.approx(1 / 3), 1.0, 1.0]


def test_logs_source_columns_and_accepted_schema_drift(caplog, monkeypatch):
    monkeypatch.setattr(
        logging.getLogger("threatflow.ingestion.epss_parser"), "disabled", False
    )
    with caplog.at_level(logging.INFO):
        rows = parse_dataset(
            gz("cve,epss,percentile,new_field\nCVE-2024-1234,0.1,0.2,value\n"),
            date(2024, 1, 1),
        )

    assert len(rows) == 1
    assert "stage=source_schema source=epss scope=csv_header" in caplog.text
    assert "status=accepted_with_drift" in caplog.text
    assert "unexpected_fields=new_field" in caplog.text
    assert "projected_fields=cve_id,epss_score,percentile,score_date" in caplog.text


def test_reject_invalid_or_duplicate_rows():
    with pytest.raises(ValueError):
        parse_dataset(gz("cve,epss,percentile\nwrong,0.1,0.2"), date.today())
    with pytest.raises(ValueError):
        parse_dataset(gz("cve,epss,percentile\nCVE-2024-1234,2,0.2"), date.today())
    with pytest.raises(ValueError):
        parse_dataset(
            gz("cve,epss,percentile\nCVE-2024-1234,.1,.2\nCVE-2024-1234,.1,.2"), date.today()
        )


@pytest.mark.parametrize(
    "body",
    [
        "cve,epss,percentile\nCVE-2024-1234,0.1,0.2,extra\n",
        "cve,epss,percentile\nCVE-2024-1234,0.1\n",
        "cve,epss,epss,percentile\nCVE-2024-1234,bad,0.1,0.2\n",
        "cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n#bad,row,data\n",
    ],
)
def test_reject_malformed_csv_structure(body):
    with pytest.raises(ValueError):
        parse_dataset(gz(body), date(2024, 1, 1))


def test_missing_columns_empty_truncated_and_invalid_percentile():
    for content in [
        gz("cve\nCVE-2024-1234"),
        gz("cve,epss,percentile\n"),
        gz("cve,epss,percentile\nCVE-2024-1234,0.1,2"),
        gz("cve,epss,percentile\nCVE-2024-1234,0.1,not-a-number"),
        gz("cve,epss,percentile\nCVE-2024-1234,0.1,0.2")[:-3],
    ]:
        with pytest.raises(ValueError):
            parse_dataset(content, date(2024, 1, 1))


def test_client_retries_429_and_stops_at_limit(monkeypatch):
    import httpx

    calls, sleeps = [], []

    def get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            return httpx.Response(
                429, headers={"Retry-After": "2"}, request=httpx.Request("GET", url)
            )
        return httpx.Response(
            200,
            content=gz("cve,epss,percentile\nCVE-2024-1234,.1,.2"),
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("threatflow.ingestion.epss_client.httpx.get", get)
    EpssClient(retries=1, sleep=sleeps.append).fetch()
    assert len(calls) == 2 and sleeps == [2]
    monkeypatch.setattr(
        "threatflow.ingestion.epss_client.httpx.get",
        lambda url, **kw: httpx.Response(404, request=httpx.Request("GET", url)),
    )
    with pytest.raises(EpssArchiveNotFound):
        EpssClient(retries=3, sleep=sleeps.append).fetch(date(2024, 1, 1))


def test_historical_404_has_explicit_missing_archive_error(monkeypatch):
    import httpx

    monkeypatch.setattr(
        "threatflow.ingestion.epss_client.httpx.get",
        lambda url, **kwargs: httpx.Response(404, request=httpx.Request("GET", url)),
    )
    with pytest.raises(EpssArchiveNotFound) as caught:
        EpssClient().fetch(date(2021, 4, 22))
    assert caught.value.score_date == date(2021, 4, 22)


def test_historical_metadata_mismatch_is_rejected():
    content = gz(
        "#model_version:v2023.03.01,score_date:2024-12-20T00:00:00Z\n"
        "cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n"
    )
    with pytest.raises(ValueError, match="does not match"):
        parse_dataset(content, date(2024, 12, 21))


def test_current_ingestion_requires_metadata_before_bronze_publish():
    from threatflow.config import Settings
    from threatflow.ingestion.epss_ingestion import ingest_epss

    class Client:
        def fetch(self, score_date):
            return gz("cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n")

    class NoStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            raise AssertionError("invalid archive must not reach accepted Bronze")

    class QuarantineStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            return SimpleNamespace(uri="s3://bronze/bronze/_quarantine/epss.csv.gz")

    with pytest.raises(ValueError, match="no authoritative score_date"):
        ingest_epss(
            client=Client(),
            settings=Settings(
                raw_storage_backend="s3",
                s3_bronze_bucket="bronze",
                _env_file=None,
            ),
            raw_store=NoStore(),
            quarantine_store=QuarantineStore(),
        )


@pytest.mark.parametrize("year,minimum", [(2021, 50_000), (2024, 130_000), (2026, 180_000)])
def test_historical_completeness_floor(year, minimum):
    from threatflow.ingestion.epss_ingestion import validate_completeness

    validate_completeness(minimum, date(year, 5, 1))
    with pytest.raises(ValueError, match="incomplete"):
        validate_completeness(minimum - 1, date(year, 5, 1))
    with pytest.raises(ValueError, match="incomplete"):
        validate_completeness(minimum, date(year, 5, 1), minimum * 2)


def test_exact_date_completeness_override_is_explicit_and_bounded():
    from threatflow.ingestion.epss_ingestion import validate_completeness

    score_date = date(2021, 4, 14)
    validate_completeness(49_000, score_date, 100_000, minimum_count_override=49_000)
    with pytest.raises(ValueError, match="minimum 49000"):
        validate_completeness(48_999, score_date, 100_000, minimum_count_override=49_000)
    with pytest.raises(ValueError, match="positive integer"):
        validate_completeness(1, score_date, minimum_count_override=0)


def test_incomplete_historical_archive_never_reaches_accepted_bronze():
    from threatflow.config import Settings
    from threatflow.ingestion.epss_ingestion import ingest_epss

    class Client:
        def fetch(self, score_date):
            return gz(
                f"#model_version:v1,score_date:{score_date}T00:00:00Z\n"
                "cve,epss,percentile\nCVE-2024-1234,0.1,0.2\n"
            )

    class NoStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            raise AssertionError("incomplete archive must not reach accepted Bronze")

    class QuarantineStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            return SimpleNamespace(uri="s3://bronze/bronze/_quarantine/epss.csv.gz")

    with pytest.raises(ValueError, match="incomplete"):
        ingest_epss(
            score_date=date(2021, 5, 1),
            client=Client(),
            settings=Settings(
                raw_storage_backend="s3",
                s3_bronze_bucket="bronze",
                _env_file=None,
            ),
            raw_store=NoStore(),
            quarantine_store=QuarantineStore(),
        )
