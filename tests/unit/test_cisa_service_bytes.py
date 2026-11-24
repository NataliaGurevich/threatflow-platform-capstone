import json
from types import SimpleNamespace

import pytest

from threatflow.config import Settings
from threatflow.ingestion.cisa_ingestion import ingest_cisa_kev


def record(number):
    return {
        "cveID": f"CVE-2024-{number:04d}",
        "vendorProject": "Vendor",
        "product": "Product",
        "vulnerabilityName": "Issue",
        "dateAdded": "2024-01-01",
        "shortDescription": "Description",
        "requiredAction": "Patch",
        "dueDate": "2024-02-01",
        "knownRansomwareCampaignUse": "Unknown",
    }


def test_invalid_catalog_is_not_published_to_accepted_bronze():
    content = (json.dumps({"vulnerabilities": []}, separators=(",", ":")) + "\n").encode()
    quarantined = []

    class Client:
        def fetch(self):
            return content

    class RawStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            raise AssertionError("invalid catalog must not reach accepted Bronze")

    class QuarantineStore:
        backend = "s3"

        def store(self, source, raw, acquired_at, extension, **kwargs):
            quarantined.append((source, raw, extension, kwargs["metadata"]))
            return SimpleNamespace(uri="s3://bronze/bronze/_quarantine/cisa.json")

    with pytest.raises(ValueError, match="empty"):
        ingest_cisa_kev(
            client=Client(),
            settings=Settings(
                raw_storage_backend="s3",
                s3_bronze_bucket="bronze",
                _env_file=None,
            ),
            raw_store=RawStore(),
            quarantine_store=QuarantineStore(),
        )
    assert quarantined == [
        (
            "cisa_kev",
            content,
            ".json",
            {
                "artifact-status": "quarantined",
                "failure-stage": "bronze-data-quality",
            },
        )
    ]


def test_catalog_below_absolute_floor_is_quarantined():
    content = json.dumps({"count": 1, "vulnerabilities": [record(1)]}).encode()
    quarantined = []

    class Client:
        def fetch(self):
            return content

    class AcceptedStore:
        backend = "s3"

        def store(self, *args, **kwargs):
            raise AssertionError("small catalog must not reach accepted Bronze")

    class QuarantineStore:
        backend = "s3"

        def store(self, source, raw, acquired_at, extension, **kwargs):
            quarantined.append(raw)
            return SimpleNamespace(uri="s3://bronze/bronze/_quarantine/cisa.json")

    class State:
        def latest_cisa_record_count(self):
            return None

    with pytest.raises(ValueError, match="minimum 100"):
        ingest_cisa_kev(
            client=Client(),
            settings=Settings(
                raw_storage_backend="s3",
                s3_bronze_bucket="bronze",
                _env_file=None,
            ),
            raw_store=AcceptedStore(),
            quarantine_store=QuarantineStore(),
            state_store=State(),
        )
    assert quarantined == [content]


def test_valid_catalog_publishes_once_to_accepted_bronze():
    content = json.dumps(
        {"count": 100, "vulnerabilities": [record(number) for number in range(1, 101)]}
    ).encode()
    stored = []

    class Client:
        def fetch(self):
            return content

    class AcceptedStore:
        backend = "s3"

        def store(self, source, raw, acquired_at, extension, **kwargs):
            stored.append((source, raw, kwargs["metadata"]))
            return SimpleNamespace(
                uri="s3://bronze/bronze/source=cisa_kev/catalog.json",
                sha256="a" * 64,
                created=True,
            )

    class State:
        def latest_cisa_record_count(self):
            return 100

    result = ingest_cisa_kev(
        client=Client(),
        settings=Settings(
            raw_storage_backend="s3",
            s3_bronze_bucket="bronze",
            _env_file=None,
        ),
        raw_store=AcceptedStore(),
        state_store=State(),
    )

    assert result.records_accepted == 100
    assert stored[0][2] == {"request-mode": "snapshot", "record-count": "100"}
