from datetime import UTC, datetime

from threatflow.derivations.cisa_changes import calculate_changes


def event(change_type, cve_id, **extra):
    return {
        "change_type": change_type,
        "cve_id": cve_id,
        **extra,
    }


def test_first_snapshot_is_baseline_not_added():
    changes = calculate_changes(
        None,
        {"CVE-2024-0001": {"cve_id": "CVE-2024-0001", "product": "A"}},
        commit_sha="a" * 40,
        committed_at=datetime(2025, 1, 1, tzinfo=UTC),
    )

    assert changes[0]["change_type"] == "baseline"
    assert changes[0]["previous_values"] is None


def test_added_modified_removed_and_unchanged():
    previous = {
        "CVE-2024-0001": {"cve_id": "CVE-2024-0001", "product": "Old", "notes": None},
        "CVE-2024-0002": {"cve_id": "CVE-2024-0002", "product": "Removed"},
        "CVE-2024-0003": {"cve_id": "CVE-2024-0003", "product": "Same"},
    }
    current = {
        "CVE-2024-0001": {"cve_id": "CVE-2024-0001", "product": "New", "notes": None},
        "CVE-2024-0003": {"cve_id": "CVE-2024-0003", "product": "Same"},
        "CVE-2024-0004": {"cve_id": "CVE-2024-0004", "product": "Added"},
    }

    changes = calculate_changes(
        previous,
        current,
        commit_sha="b" * 40,
        committed_at=datetime(2025, 1, 2, tzinfo=UTC),
    )

    assert [(change["change_type"], change["cve_id"]) for change in changes] == [
        ("added", "CVE-2024-0004"),
        ("removed", "CVE-2024-0002"),
        ("modified", "CVE-2024-0001"),
    ]
    modified = changes[-1]
    assert modified["changed_fields"] == ["product"]
    assert modified["previous_values"] == {"product": "Old"}
    assert modified["current_values"] == {"product": "New"}
