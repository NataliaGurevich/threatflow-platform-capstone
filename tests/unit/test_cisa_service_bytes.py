import hashlib
import json
from types import SimpleNamespace

from threatflow.config import Settings
from threatflow.ingestion.cisa_ingestion import ingest_cisa_kev


def test_ingestion_preserves_response_bytes_before_parsing(tmp_path, monkeypatch):
    content = (json.dumps({"vulnerabilities": []}, separators=(",", ":")) + "\n").encode()
    observed = {}

    class Client:
        def fetch(self):
            return content

    def store(source, raw, acquired_at, extension, *, raw_data_dir):
        observed["bytes"] = raw
        path = tmp_path / "artifact.json"
        path.write_bytes(raw)
        return SimpleNamespace(
            path=path, sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw)
        )

    class Engine:
        def begin(self):
            class Context:
                def __enter__(self):
                    return object()

                def __exit__(self, *args):
                    return False

            return Context()

        def dispose(self):
            pass

    monkeypatch.setattr("threatflow.ingestion.cisa_ingestion.store_raw_artifact", store)
    monkeypatch.setattr("threatflow.ingestion.cisa_ingestion.create_engine", lambda _: Engine())
    monkeypatch.setattr(
        "threatflow.ingestion.cisa_ingestion.upsert_records", lambda session, records: (0, 0)
    )
    result = ingest_cisa_kev(client=Client(), settings=Settings(raw_data_dir=str(tmp_path)))

    assert observed["bytes"] == content
    assert (tmp_path / "artifact.json").read_bytes() == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.downloaded_bytes == len(content)
    assert result.parsed_records == 0
