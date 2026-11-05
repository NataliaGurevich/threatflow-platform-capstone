import json
from datetime import UTC, date, datetime, timedelta
from io import StringIO

import pytest

import threatflow.orchestration.backfill_status as backfill_status
from threatflow.orchestration.backfill_status import (
    ActiveBackfill,
    BackfillProgress,
    BackfillStatus,
    classify_progress,
    main,
    read_checkpoint_progress,
)


def checkpoint_payload():
    return {
        "plan": {
            "sources": ["epss"],
            "start": "2025-01-01",
            "end": "2025-02-15",
            "interval_days": 31,
            "nvd_mode": "published",
            "chunk_days": 7,
        },
        "completed_run_ids": ["range-eaf0c44c9f9d-20250101-20250131"],
    }


def active_progress(*, state="running", heartbeat_age_seconds=10, remaining_windows=1):
    return BackfillProgress(
        total_windows=2,
        completed_windows=2 - remaining_windows,
        remaining_windows=remaining_windows,
        active=ActiveBackfill(
            run_id="range-test",
            start=date(2025, 2, 1),
            end=date(2025, 2, 15),
            state=state,
        ),
        updated_at=datetime(2026, 11, 5, 12, 0, tzinfo=UTC),
        heartbeat_age_seconds=heartbeat_age_seconds,
    )


def test_reads_checkpoint_progress(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps(checkpoint_payload()))

    assert read_checkpoint_progress(checkpoint) == BackfillProgress(
        total_windows=2,
        completed_windows=1,
        remaining_windows=1,
    )


def test_rejects_duplicate_completed_run_ids(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    payload = checkpoint_payload()
    payload["completed_run_ids"] *= 2
    checkpoint.write_text(json.dumps(payload))

    with pytest.raises(ValueError, match="duplicate or unknown"):
        read_checkpoint_progress(checkpoint)


def test_cli_prints_progress(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps(checkpoint_payload()))
    output = StringIO()

    exit_code = main(["--checkpoint", str(checkpoint)], output=output)

    assert exit_code == 2
    assert output.getvalue().splitlines() == [
        "Status: UNKNOWN",
        "Total windows: 2",
        "Completed windows: 1",
        "Remaining windows: 1",
        "Active window: none",
    ]


def test_cli_reports_missing_checkpoint(tmp_path):
    error = StringIO()

    exit_code = main(["--checkpoint", str(tmp_path / "missing.json")], error=error)

    assert exit_code == 2
    assert "Error:" in error.getvalue()


def test_reads_and_prints_active_window(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    payload = checkpoint_payload()
    payload["active"] = {
        "run_id": "range-eaf0c44c9f9d-20250201-20250215",
        "start": "2025-02-01",
        "end": "2025-02-15",
        "state": "running",
    }
    payload["updated_at"] = "2026-11-05T12:00:00+00:00"
    checkpoint.write_text(json.dumps(payload))
    output = StringIO()

    progress = read_checkpoint_progress(
        checkpoint,
        now=datetime(2026, 11, 5, 12, 0, 42, tzinfo=UTC),
    )
    exit_code = main(
        [
            "--checkpoint",
            str(checkpoint),
            "--stall-after-minutes",
            "1000000",
        ],
        output=output,
    )

    assert progress.active == ActiveBackfill(
        run_id="range-eaf0c44c9f9d-20250201-20250215",
        start=date(2025, 2, 1),
        end=date(2025, 2, 15),
        state="running",
    )
    assert progress.heartbeat_age_seconds == 42
    assert exit_code == 0
    assert "Status: RUNNING" in output.getvalue()
    assert "Active window: 2025-02-01..2025-02-15" in output.getvalue()
    assert "Active state: running" in output.getvalue()
    assert "Heartbeat age:" in output.getvalue()
    assert "Updated at: 2026-11-05T12:00:00+00:00" in output.getvalue()


@pytest.mark.parametrize("state", ["submitting", "queued", "running"])
def test_classifies_fresh_nonterminal_states_as_running(state):
    assert classify_progress(active_progress(state=state)) is BackfillStatus.RUNNING


def test_classifies_old_heartbeat_as_stalled():
    progress = active_progress(heartbeat_age_seconds=1_801)

    assert classify_progress(progress) is BackfillStatus.STALLED


def test_stall_threshold_boundary_is_still_running():
    progress = active_progress(heartbeat_age_seconds=1_800)

    assert classify_progress(progress) is BackfillStatus.RUNNING


def test_classifies_failed_active_run():
    assert classify_progress(active_progress(state="failed")) is BackfillStatus.FAILED


def test_classifies_completed_checkpoint():
    progress = BackfillProgress(total_windows=2, completed_windows=2, remaining_windows=0)

    assert classify_progress(progress) is BackfillStatus.COMPLETED


@pytest.mark.parametrize(
    "progress",
    [
        BackfillProgress(total_windows=2, completed_windows=1, remaining_windows=1),
        active_progress(state="success"),
        active_progress(state="unexpected"),
    ],
)
def test_classifies_ambiguous_progress_as_unknown(progress):
    assert classify_progress(progress) is BackfillStatus.UNKNOWN


def test_rejects_nonpositive_stall_threshold():
    with pytest.raises(ValueError, match="positive"):
        classify_progress(active_progress(), stall_after=timedelta(0))


@pytest.mark.parametrize(
    ("progress", "expected_status", "expected_exit_code"),
    [
        (active_progress(), BackfillStatus.RUNNING, 0),
        (active_progress(heartbeat_age_seconds=1_801), BackfillStatus.STALLED, 2),
        (active_progress(state="failed"), BackfillStatus.FAILED, 1),
        (
            BackfillProgress(total_windows=2, completed_windows=2, remaining_windows=0),
            BackfillStatus.COMPLETED,
            0,
        ),
        (
            BackfillProgress(total_windows=2, completed_windows=1, remaining_windows=1),
            BackfillStatus.UNKNOWN,
            2,
        ),
    ],
)
def test_cli_prints_status_and_returns_matching_exit_code(
    monkeypatch, progress, expected_status, expected_exit_code
):
    monkeypatch.setattr(backfill_status, "read_checkpoint_progress", lambda _path: progress)
    output = StringIO()

    exit_code = main(["--checkpoint", "unused.json"], output=output)

    assert output.getvalue().splitlines()[0] == f"Status: {expected_status}"
    assert exit_code == expected_exit_code


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf"])
def test_cli_rejects_invalid_stall_threshold(value):
    with pytest.raises(SystemExit) as exc_info:
        main(["--stall-after-minutes", value])

    assert exc_info.value.code == 2
