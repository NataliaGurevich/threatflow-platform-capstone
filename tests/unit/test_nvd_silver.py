import json
from datetime import UTC, datetime
from hashlib import sha256

import pyarrow.compute as pc
import pyarrow.parquet as pq
import pytest

from threatflow.raw_storage import RawArtifactRef
from threatflow.transformation.nvd_silver import NvdSilverPageInput, transform_nvd_window
from threatflow.transformation.nvd_window import (
    build_nvd_window_manifest,
    encode_nvd_window_manifest,
)


def cve(cve_id, modified):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-11-01T00:00:00.000Z",
            "lastModified": modified,
            "descriptions": [{"lang": "en", "value": f"description {modified}"}],
            "metrics": {},
            "references": [{"url": "https://example.test"}],
        }
    }


def page(start, total, records):
    return json.dumps(
        {
            "startIndex": start,
            "resultsPerPage": len(records),
            "totalResults": total,
            "vulnerabilities": records,
        }
    ).encode()


def fixture():
    contents = [
        page(
            0,
            3,
            [
                cve("CVE-2026-1000", "2026-11-10T00:00:00Z"),
                cve("CVE-2026-1001", "2026-11-11T00:00:00Z"),
            ],
        ),
        page(2, 3, [cve("CVE-2026-1000", "2026-11-12T00:00:00Z")]),
    ]
    artifacts = []
    for index, content in enumerate(contents):
        digest = sha256(content).hexdigest()
        artifacts.append(
            RawArtifactRef(
                "nvd",
                digest,
                f"s3://bronze/bronze/source=nvd/sha256={digest}.json",
                "json",
                "application/json",
                len(content),
                True,
                "s3",
                "bronze",
                f"bronze/source=nvd/sha256={digest}.json",
                f"version-{index}",
            )
        )
    manifest = build_nvd_window_manifest(
        mode="modified",
        requested_start=datetime(2026, 11, 10, tzinfo=UTC),
        requested_end=datetime(2026, 11, 13, tzinfo=UTC),
        acquired_at=datetime(2026, 11, 13, 3, tzinfo=UTC),
        total_results=3,
        pages=[(artifacts[0], 0, 2), (artifacts[1], 2, 1)],
    )
    encoded = encode_nvd_window_manifest(manifest)
    inputs = [
        NvdSilverPageInput(lineage, content)
        for lineage, content in zip(manifest.pages, contents, strict=True)
    ]
    return encoded, inputs


def test_complete_window_commits_and_reuses_immutable_partition(tmp_path):
    encoded, pages = fixture()
    digest = sha256(encoded).hexdigest()
    options = {
        "window_sha256": digest,
        "window_uri": f"s3://bronze/bronze/source=nvd/sha256={digest}.window.json",
        "window_version_id": "window-version",
        "pages": pages,
        "output_root": tmp_path,
    }

    created = transform_nvd_window(encoded, **options)
    reused = transform_nvd_window(encoded, **options)

    assert created.created is True
    assert reused.created is False
    assert created.record_count == 2
    table = pq.read_table(created.parquet_path)
    assert table.num_rows == 2
    latest = table.filter(pc.equal(table["cve_id"], "CVE-2026-1000")).to_pylist()[0]
    assert latest["last_modified"] == datetime(2026, 11, 12, tzinfo=UTC)
    manifest = json.loads(open(created.manifest_path).read())
    assert manifest["source"]["version_id"] == "window-version"
    assert [item["version_id"] for item in manifest["source"]["pages"]] == [
        "version-0",
        "version-1",
    ]


def test_missing_or_corrupt_page_fails_before_publication(tmp_path):
    encoded, pages = fixture()
    digest = sha256(encoded).hexdigest()
    options = {
        "window_sha256": digest,
        "window_uri": "s3://bronze/window",
        "window_version_id": "window-version",
        "output_root": tmp_path,
    }
    with pytest.raises(ValueError, match="incomplete"):
        transform_nvd_window(encoded, pages=pages[:1], **options)
    with pytest.raises(ValueError, match="size|SHA-256"):
        transform_nvd_window(
            encoded,
            pages=[pages[0], NvdSilverPageInput(pages[1].lineage, pages[1].content + b"x")],
            **options,
        )
    assert list(tmp_path.rglob("_manifest.json")) == []


def test_published_and_modified_are_distinct_partitions(tmp_path):
    encoded, pages = fixture()
    modified_digest = sha256(encoded).hexdigest()
    modified = transform_nvd_window(
        encoded,
        window_sha256=modified_digest,
        window_uri="s3://bronze/modified",
        window_version_id="modified-version",
        pages=pages,
        output_root=tmp_path,
    )
    value = json.loads(encoded)
    value["mode"] = "published"
    published_bytes = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    published = transform_nvd_window(
        published_bytes,
        window_sha256=sha256(published_bytes).hexdigest(),
        window_uri="s3://bronze/published",
        window_version_id="published-version",
        pages=pages,
        output_root=tmp_path,
    )
    assert modified.parquet_path != published.parquet_path
    assert "mode=modified" in modified.parquet_path
    assert "mode=published" in published.parquet_path
