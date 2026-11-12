import hashlib
import json
from types import SimpleNamespace

import pytest

from threatflow.config import Settings
from threatflow.ingestion.cisa_ingestion import ingest_cisa_kev


def test_ingestion_preserves_response_bytes_before_parsing(tmp_path, monkeypatch):
    content = (json.dumps({"vulnerabilities": []}, separators=(",", ":")) + "\n").encode()
    observed = {}

    class Client:
        def fetch(self):
            return content

    class RawStore:
        def store(self, source, raw, acquired_at, extension, *, content_type=None):
            observed["bytes"] = raw
            path = tmp_path / "artifact.json"
            path.write_bytes(raw)
            return SimpleNamespace(
                uri=str(path),
                sha256=hashlib.sha256(raw).hexdigest(),
                size_bytes=len(raw),
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

    def no_database(_):
        raise AssertionError("database must not be opened for invalid catalog")

    class NoReplica:
        backend = "s3"

        def store(self, *args, **kwargs):
            raise AssertionError("invalid catalog must not reach S3")

    monkeypatch.setattr("threatflow.ingestion.cisa_ingestion.create_engine", no_database)
    monkeypatch.setattr(
        "threatflow.ingestion.cisa_ingestion.upsert_records", lambda session, records: (0, 0)
    )
    with pytest.raises(ValueError, match="empty"):
        ingest_cisa_kev(
            client=Client(),
            settings=Settings(raw_data_dir=str(tmp_path), _env_file=None),
            raw_store=RawStore(),
            replica_store=NoReplica(),
        )

    assert observed["bytes"] == content
    assert (tmp_path / "artifact.json").read_bytes() == content
