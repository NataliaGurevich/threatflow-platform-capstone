import json
from datetime import UTC, date, datetime, timedelta

import pytest

from threatflow.raw_storage import calculate_sha256
from threatflow.transformation.nvd_silver_bootstrap import (
    NvdBootstrapPage,
    NvdBootstrapSelection,
    NvdBootstrapWindow,
    NvdBootstrapWindowError,
    run_nvd_silver_bootstrap,
    select_nvd_bootstrap_windows,
)


class MemoryStore:
    def __init__(self, values):
        self.values = values

    def read(self, artifact):
        return self.values[artifact]


def cve(cve_id, modified="2026-11-01T00:00:00Z"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2022-01-01T00:00:00Z",
            "lastModified": modified,
            "descriptions": [{"lang": "en", "value": "description"}],
            "metrics": {},
        }
    }


def raw_page(start, total, records):
    return json.dumps(
        {
            "startIndex": start,
            "resultsPerPage": len(records),
            "totalResults": total,
            "vulnerabilities": records,
        }
    ).encode()


def page(
    artifact_id,
    content,
    *,
    mode="published",
    start=datetime(2022, 1, 1, tzinfo=UTC),
    end=datetime(2022, 1, 8, tzinfo=UTC),
    page_start=0,
):
    return NvdBootstrapPage(
        artifact_id,
        calculate_sha256(content),
        mode,
        start,
        end,
        page_start,
        len(json.loads(content)["vulnerabilities"]),
        len(content),
        datetime(2026, 11, 16, tzinfo=UTC),
        f"memory://{artifact_id}",
    )


def test_selection_groups_pages_and_filters_overlapping_five_year_range():
    first = raw_page(0, 2, [cve("CVE-2022-0001")])
    second = raw_page(1, 2, [cve("CVE-2022-0002")])
    old = raw_page(0, 1, [cve("CVE-2019-0001")])
    pages = [
        page(2, second, page_start=1),
        page(1, first),
        page(
            3,
            old,
            start=datetime(2019, 1, 1, tzinfo=UTC),
            end=datetime(2019, 1, 8, tzinfo=UTC),
        ),
    ]

    selection = select_nvd_bootstrap_windows(
        pages, start_date=date(2022, 1, 1), end_date=date(2026, 11, 16)
    )

    assert selection.available == 1
    assert [item.page_start_index for item in selection.windows[0].pages] == [0, 1]


def test_dry_run_reports_incomplete_window_without_writes(tmp_path):
    content = raw_page(0, 2, [cve("CVE-2022-0001")])
    candidate = page(1, content)
    selection = NvdBootstrapSelection(
        1,
        (
            NvdBootstrapWindow(
                "published", candidate.requested_start, candidate.requested_end, (candidate,)
            ),
        ),
        None,
        None,
    )

    result = run_nvd_silver_bootstrap(
        selection,
        local_store=MemoryStore({candidate.local_uri: content}),
        output_root=tmp_path,
        dry_run=True,
    )

    assert result.verified == 0
    assert len(result.issues) == 1
    assert "incomplete" in result.issues[0].message
    assert not any(tmp_path.iterdir())


def test_apply_creates_and_reuses_local_lineage_partition(tmp_path):
    first_content = raw_page(0, 2, [cve("CVE-2022-0001")])
    second_content = raw_page(
        1, 2, [cve("CVE-2022-0002", "2026-11-15T00:00:00Z")]
    )
    first = page(1, first_content)
    second = page(2, second_content, page_start=1)
    selection = NvdBootstrapSelection(
        1,
        (
            NvdBootstrapWindow(
                "published", first.requested_start, first.requested_end, (first, second)
            ),
        ),
        None,
        None,
    )
    store = MemoryStore({first.local_uri: first_content, second.local_uri: second_content})

    created = run_nvd_silver_bootstrap(
        selection, local_store=store, output_root=tmp_path, dry_run=False
    )
    replay = run_nvd_silver_bootstrap(
        selection, local_store=store, output_root=tmp_path, dry_run=False
    )

    assert created.created == 1
    assert replay.reused == 1
    manifest = json.loads(next(tmp_path.rglob("_manifest.json")).read_text())
    assert "version_id" not in manifest["source"]
    assert {item["backend"] for item in manifest["source"]["pages"]} == {"local"}


def test_apply_stops_after_prior_window_commit(tmp_path):
    good_content = raw_page(0, 1, [cve("CVE-2022-0001")])
    bad_content = raw_page(0, 2, [cve("CVE-2023-0001")])
    first = page(1, good_content)
    second = page(
        2,
        bad_content,
        start=first.requested_start + timedelta(days=7),
        end=first.requested_end + timedelta(days=7),
    )
    selection = NvdBootstrapSelection(
        2,
        (
            NvdBootstrapWindow("published", first.requested_start, first.requested_end, (first,)),
            NvdBootstrapWindow(
                "published", second.requested_start, second.requested_end, (second,)
            ),
        ),
        None,
        None,
    )

    with pytest.raises(NvdBootstrapWindowError, match="after 1 committed windows"):
        run_nvd_silver_bootstrap(
            selection,
            local_store=MemoryStore(
                {first.local_uri: good_content, second.local_uri: bad_content}
            ),
            output_root=tmp_path,
            dry_run=False,
        )
