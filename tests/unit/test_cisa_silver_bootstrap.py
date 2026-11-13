import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.cisa_silver_bootstrap import (
    CisaBootstrapCandidate,
    CisaBootstrapItemError,
    CisaBootstrapSelection,
    run_cisa_silver_bootstrap,
    select_cisa_bootstrap_candidates,
)

ACQUIRED_AT = datetime(2026, 11, 13, 10, 0, tzinfo=UTC)


def catalog_bytes(cve="CVE-2026-1234"):
    return json.dumps(
        {
            "catalogVersion": "2026.11.13",
            "dateReleased": "2026-11-13T09:00:00Z",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": cve,
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Issue",
                    "dateAdded": "2026-11-01",
                    "shortDescription": "Description",
                    "requiredAction": "Patch",
                    "dueDate": "2026-11-20",
                    "knownRansomwareCampaignUse": "Unknown",
                }
            ],
        }
    ).encode()


def candidate(artifact_id, content, *, mode="snapshot", revision=None, offset=0):
    return CisaBootstrapCandidate(
        artifact_id=artifact_id,
        sha256=calculate_sha256(content),
        request_mode=mode,
        source_revision=revision,
        record_count=1,
        size_bytes=len(content),
        acquired_at=ACQUIRED_AT + timedelta(minutes=offset),
        observed_at=ACQUIRED_AT + timedelta(minutes=offset),
        local_uri=f"memory://{artifact_id}",
        lineage_uri=f"s3://bronze/{artifact_id}.json",
        source_version_id=f"version-{artifact_id}",
    )


class MemoryStore:
    def __init__(self, values):
        self.values = values

    def read(self, artifact):
        return self.values[artifact]


def test_selection_orders_limits_and_keeps_snapshot_and_git_history():
    current = candidate(2, catalog_bytes(), offset=2)
    history = candidate(1, catalog_bytes("CVE-2025-1234"), mode="git_history", revision="a" * 40)
    selection = select_cisa_bootstrap_candidates([current, history], limit=1)
    assert selection.available == 2
    assert selection.candidates == (history,)


def test_selection_rejects_invalid_mode_revision_and_conflicting_identity():
    content = catalog_bytes()
    with pytest.raises(ValueError, match="unsupported"):
        select_cisa_bootstrap_candidates(
            [replace(candidate(1, content), request_mode="git_history_invalid")]  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="invalid Git"):
        select_cisa_bootstrap_candidates(
            [candidate(1, content, mode="git_history", revision="short")]
        )
    first = candidate(1, content, mode="git_history", revision="a" * 40)
    second = candidate(
        2, catalog_bytes("CVE-2026-9999"), mode="git_history", revision="a" * 40
    )
    with pytest.raises(ValueError, match="conflicting"):
        select_cisa_bootstrap_candidates([first, second])


def test_dry_run_validates_bytes_catalog_count_and_existing_commit(tmp_path):
    good_content = catalog_bytes()
    bad_content = catalog_bytes("CVE-2026-9999")
    good = candidate(1, good_content)
    bad = replace(candidate(2, bad_content), record_count=2)
    selection = CisaBootstrapSelection(2, (good, bad))
    result = run_cisa_silver_bootstrap(
        selection,
        local_store=MemoryStore({good.local_uri: good_content, bad.local_uri: bad_content}),
        output_root=tmp_path,
        dry_run=True,
    )
    assert result.verified == result.planned == 1
    assert result.created == result.reused == 0
    assert len(result.issues) == 1
    assert "record count mismatch" in result.issues[0].message
    assert not any(tmp_path.iterdir())


def test_apply_is_resumable_and_preserves_s3_lineage(tmp_path):
    first_content = catalog_bytes()
    second_content = catalog_bytes("CVE-2026-9999")
    first = candidate(1, first_content)
    second = candidate(2, second_content, offset=1)
    selection = CisaBootstrapSelection(2, (first, second))
    store = MemoryStore({first.local_uri: first_content, second.local_uri: second_content})

    result = run_cisa_silver_bootstrap(
        selection, local_store=store, output_root=tmp_path, dry_run=False
    )
    assert result.created == 2
    replay = run_cisa_silver_bootstrap(
        selection, local_store=store, output_root=tmp_path, dry_run=False
    )
    assert replay.created == 0
    assert replay.reused == 2

    manifests = list(tmp_path.rglob("_manifest.json"))
    payloads = [json.loads(path.read_text()) for path in manifests]
    assert {payload["source"]["version_id"] for payload in payloads} == {
        "version-1",
        "version-2",
    }


def test_apply_stops_after_failure_and_retry_reuses_prior_commit(tmp_path):
    first_content = catalog_bytes()
    second_content = catalog_bytes("CVE-2026-9999")
    first = candidate(1, first_content)
    second = candidate(2, second_content, offset=1)
    selection = CisaBootstrapSelection(2, (first, second))
    failing = MemoryStore({first.local_uri: first_content, second.local_uri: b"corrupt"})
    with pytest.raises(CisaBootstrapItemError, match="after 1 committed"):
        run_cisa_silver_bootstrap(
            selection, local_store=failing, output_root=tmp_path, dry_run=False
        )

    retry = run_cisa_silver_bootstrap(
        selection,
        local_store=MemoryStore(
            {first.local_uri: first_content, second.local_uri: second_content}
        ),
        output_root=tmp_path,
        dry_run=False,
    )
    assert retry.reused == 1
    assert retry.created == 1
