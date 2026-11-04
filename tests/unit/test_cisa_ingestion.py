import json

import httpx
import pytest

from threatflow.ingestion.cisa_client import CisaClient
from threatflow.ingestion.cisa_parser import parse_catalog

RECORD = {
    "cveID": "CVE-2024-1234",
    "vendorProject": "Vendor",
    "product": "Product",
    "vulnerabilityName": "Issue",
    "dateAdded": "2024-01-01",
    "shortDescription": "Description",
    "requiredAction": "Patch",
    "dueDate": "2024-02-01",
    "knownRansomwareCampaignUse": "Unknown",
}


def test_parser_and_empty_catalog():
    assert (
        parse_catalog(json.dumps({"vulnerabilities": [RECORD]}).encode())[0]["cve_id"]
        == "CVE-2024-1234"
    )
    with pytest.raises(ValueError, match="empty"):
        parse_catalog(b'{"vulnerabilities":[]}')


def test_declared_catalog_count():
    with pytest.raises(ValueError, match="count"):
        parse_catalog(json.dumps({"count": 2, "vulnerabilities": [RECORD]}).encode())


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"vulnerabilities":[{}]}',
        b'{"vulnerabilities":[{"cveID":"bad"}]}',
        b'{"vulnerabilities":[{"cveID":"CVE-2024-1","vendorProject":"v","product":"p","vulnerabilityName":"n","dateAdded":"bad","shortDescription":"s","requiredAction":"a","dueDate":"2024-01-01","knownRansomwareCampaignUse":"Unknown"}]}',
    ],
)
def test_parser_rejects_invalid(body):
    with pytest.raises(ValueError):
        parse_catalog(body)


def test_http_download_and_status(monkeypatch):
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **kw: httpx.Response(
            200, content=b"exact", request=httpx.Request("GET", "https://cisa.test")
        ),
    )
    assert CisaClient().fetch() == b"exact"
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **kw: httpx.Response(404, request=httpx.Request("GET", "https://cisa.test")),
    )
    with pytest.raises(httpx.HTTPStatusError):
        CisaClient(retries=0).fetch()


def test_retries_transient_server_error(monkeypatch):
    responses = [
        httpx.Response(503, request=httpx.Request("GET", "https://cisa.test")),
        httpx.Response(200, content=b"ok", request=httpx.Request("GET", "https://cisa.test")),
    ]
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: responses.pop(0))
    monkeypatch.setattr("threatflow.ingestion.cisa_client.time.sleep", lambda _: None)
    assert CisaClient(retries=1).fetch() == b"ok"
    assert not responses


def test_retries_connection_error(monkeypatch):
    calls = 0

    def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise httpx.ConnectError("offline", request=httpx.Request("GET", "https://cisa.test"))
        return httpx.Response(200, content=b"ok", request=httpx.Request("GET", "https://cisa.test"))

    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr("threatflow.ingestion.cisa_client.time.sleep", lambda _: None)
    assert CisaClient(retries=1).fetch() == b"ok"
    assert calls == 2


def test_retry_limit_and_final_error(monkeypatch):
    calls = 0

    def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("offline", request=httpx.Request("GET", "https://cisa.test"))

    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr("threatflow.ingestion.cisa_client.time.sleep", lambda _: None)
    with pytest.raises(httpx.ConnectError, match="offline"):
        CisaClient(retries=2).fetch()
    assert calls == 3


def test_does_not_retry_nonretryable_client_error(monkeypatch):
    calls = 0

    def get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return httpx.Response(404, request=httpx.Request("GET", "https://cisa.test"))

    monkeypatch.setattr(httpx, "get", get)
    with pytest.raises(httpx.HTTPStatusError):
        CisaClient(retries=3).fetch()
    assert calls == 1
