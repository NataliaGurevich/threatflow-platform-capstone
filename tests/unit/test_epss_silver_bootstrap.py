import gzip
from dataclasses import replace
from datetime import UTC, date, datetime

import pytest

from threatflow.raw_storage import RawArtifactRef, calculate_sha256
from threatflow.transformation import epss_silver
from threatflow.transformation.epss_silver import EpssSilverResult
from threatflow.transformation.epss_silver_bootstrap import (
    EpssBootstrapCandidate,
    EpssBootstrapItemError,
    EpssBootstrapSelection,
    run_epss_silver_bootstrap,
    select_epss_bootstrap_candidates,
)

ACQUIRED_AT = datetime(2026, 11, 12, 6, 0, tzinfo=UTC)


class MemoryLocalStore:
    def __init__(self, objects: dict[str, bytes]):
        self.objects = objects

    def read(self, artifact: RawArtifactRef | str) -> bytes:
        uri = artifact.uri if isinstance(artifact, RawArtifactRef) else artifact
        return self.objects[uri]


def candidate(artifact_id: int, score_date: date, content: bytes) -> EpssBootstrapCandidate:
    sha256 = calculate_sha256(content)
    return EpssBootstrapCandidate(
        artifact_id=artifact_id,
        sha256=sha256,
        score_date=score_date,
        record_count=artifact_id * 10,
        size_bytes=len(content),
        acquired_at=ACQUIRED_AT,
        local_uri=f"memory://{artifact_id}",
        lineage_uri=f"s3://bronze/{sha256}.csv.gz",
    )


def silver_result(item: EpssBootstrapCandidate, *, created: bool) -> EpssSilverResult:
    return EpssSilverResult(
        dataset="epss_scores",
        score_date=item.score_date,
        source_sha256=item.sha256,
        record_count=item.record_count,
        parquet_path=f"/silver/{item.score_date}/epss.parquet",
        manifest_path=f"/silver/{item.score_date}/_manifest.json",
        parquet_sha256="f" * 64,
        parquet_size_bytes=123,
        created=created,
    )


def epss_raw(score_date: date) -> bytes:
    return gzip.compress(
        (
            f"#model_version:v2025.03.14,score_date:{score_date}T00:00:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2026-0001,0.1,0.2\n"
            "CVE-2026-0002,0.3,0.4\n"
        ).encode()
    )


def test_selection_is_ordered_reports_full_range_gaps_and_applies_limit() -> None:
    first = candidate(1, date(2026, 11, 1), b"first")
    third = candidate(3, date(2026, 11, 3), b"third")

    selection = select_epss_bootstrap_candidates([third, first], limit=1)

    assert selection.available == 2
    assert selection.candidates == (first,)
    assert selection.start_date == date(2026, 11, 1)
    assert selection.end_date == date(2026, 11, 3)
    assert selection.gap_dates == (date(2026, 11, 2),)


def test_selection_rejects_multiple_raw_hashes_for_one_score_date() -> None:
    first = candidate(1, date(2026, 11, 1), b"first")
    correction = candidate(2, date(2026, 11, 1), b"corrected")

    with pytest.raises(ValueError, match="multiple EPSS Raw artifacts"):
        select_epss_bootstrap_candidates([first, correction])


def test_dry_run_verifies_raw_and_reports_planned_reused_and_issues(tmp_path) -> None:
    planned = candidate(1, date(2026, 11, 1), b"planned")
    reused = candidate(2, date(2026, 11, 2), b"reused")
    corrupt = candidate(3, date(2026, 11, 3), b"expected")
    selection = EpssBootstrapSelection(
        available=3,
        candidates=(planned, reused, corrupt),
        start_date=planned.score_date,
        end_date=corrupt.score_date,
        gap_dates=(),
    )
    transformed = False

    def never_transform(*args, **kwargs):
        nonlocal transformed
        transformed = True
        raise AssertionError("dry-run must not transform")

    def verify(**kwargs):
        if kwargs["score_date"] == reused.score_date:
            return silver_result(reused, created=False)
        return None

    result = run_epss_silver_bootstrap(
        selection,
        local_store=MemoryLocalStore(
            {
                planned.local_uri: b"planned",
                reused.local_uri: b"reused",
                corrupt.local_uri: b"corrupt!",
            }
        ),
        output_root=tmp_path,
        dry_run=True,
        transformer=never_transform,
        committed_verifier=verify,
    )

    assert transformed is False
    assert result.selected == 3
    assert result.verified == 2
    assert result.planned == 1
    assert result.reused == 1
    assert result.created == 0
    assert result.record_count == planned.record_count + reused.record_count
    assert len(result.issues) == 1
    assert "SHA-256 mismatch" in result.issues[0].message


def test_apply_stops_after_failure_and_reports_committed_progress(tmp_path) -> None:
    first = candidate(1, date(2026, 11, 1), b"first")
    second = candidate(2, date(2026, 11, 2), b"second")
    selection = EpssBootstrapSelection(
        available=2,
        candidates=(first, second),
        start_date=first.score_date,
        end_date=second.score_date,
        gap_dates=(),
    )
    calls: list[date] = []

    def transform(content, **kwargs):
        calls.append(kwargs["score_date"])
        if kwargs["score_date"] == second.score_date:
            raise ValueError("simulated transform failure")
        return silver_result(first, created=True)

    with pytest.raises(
        EpssBootstrapItemError,
        match="after 1 committed partitions: simulated transform failure",
    ):
        run_epss_silver_bootstrap(
            selection,
            local_store=MemoryLocalStore(
                {first.local_uri: b"first", second.local_uri: b"second"}
            ),
            output_root=tmp_path,
            dry_run=False,
            transformer=transform,
        )

    assert calls == [first.score_date, second.score_date]


def test_apply_counts_created_and_reused_partitions(tmp_path) -> None:
    first = candidate(1, date(2026, 11, 1), b"first")
    second = candidate(2, date(2026, 11, 2), b"second")
    selection = EpssBootstrapSelection(
        available=2,
        candidates=(first, second),
        start_date=first.score_date,
        end_date=second.score_date,
        gap_dates=(),
    )

    def transform(content, **kwargs):
        item = first if kwargs["score_date"] == first.score_date else second
        return silver_result(item, created=item is second)

    result = run_epss_silver_bootstrap(
        selection,
        local_store=MemoryLocalStore(
            {first.local_uri: b"first", second.local_uri: b"second"}
        ),
        output_root=tmp_path,
        dry_run=False,
        transformer=transform,
    )

    assert result.verified == 2
    assert result.created == 1
    assert result.reused == 1
    assert result.planned == 0
    assert result.record_count == first.record_count + second.record_count


def test_apply_with_real_transformer_is_replay_safe(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(epss_silver, "validate_completeness", lambda *args: None)
    first_content = epss_raw(date(2026, 11, 1))
    second_content = epss_raw(date(2026, 11, 2))
    first = replace(
        candidate(1, date(2026, 11, 1), first_content),
        record_count=2,
    )
    second = replace(
        candidate(2, date(2026, 11, 2), second_content),
        record_count=2,
    )
    selection = EpssBootstrapSelection(
        available=2,
        candidates=(first, second),
        start_date=first.score_date,
        end_date=second.score_date,
        gap_dates=(),
    )
    store = MemoryLocalStore(
        {first.local_uri: first_content, second.local_uri: second_content}
    )

    created = run_epss_silver_bootstrap(
        selection,
        local_store=store,
        output_root=tmp_path,
        dry_run=False,
    )
    replayed = run_epss_silver_bootstrap(
        selection,
        local_store=store,
        output_root=tmp_path,
        dry_run=False,
    )

    assert created.created == 2
    assert created.reused == 0
    assert replayed.created == 0
    assert replayed.reused == 2
