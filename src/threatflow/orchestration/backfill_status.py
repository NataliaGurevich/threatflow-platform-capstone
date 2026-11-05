"""Read-only progress reporting for resumable backfill checkpoints."""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TextIO

from threatflow.orchestration.backfill_controller import (
    BackfillPlan,
    backfill_run_id,
    validate_plan,
)


@dataclass(frozen=True)
class ActiveBackfill:
    """The Airflow run currently recorded in the checkpoint."""

    run_id: str
    start: date
    end: date
    state: str


class BackfillStatus(StrEnum):
    """Operator-facing state derived from a checkpoint."""

    RUNNING = "RUNNING"
    STALLED = "STALLED"
    FAILED = "FAILED"
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class BackfillProgress:
    """Counts derived from a backfill plan and its completed run IDs."""

    total_windows: int
    completed_windows: int
    remaining_windows: int
    active: ActiveBackfill | None = None
    updated_at: datetime | None = None
    heartbeat_age_seconds: int | None = None


def classify_progress(
    progress: BackfillProgress,
    *,
    stall_after: timedelta = timedelta(minutes=30),
) -> BackfillStatus:
    """Classify validated checkpoint progress without contacting Airflow."""
    if stall_after <= timedelta(0):
        raise ValueError("stall threshold must be positive")
    if progress.remaining_windows == 0:
        return BackfillStatus.COMPLETED if progress.active is None else BackfillStatus.UNKNOWN
    if progress.active is None:
        return BackfillStatus.UNKNOWN
    if progress.active.state == "failed":
        return BackfillStatus.FAILED
    if progress.active.state not in {"submitting", "queued", "running"}:
        return BackfillStatus.UNKNOWN
    if progress.heartbeat_age_seconds is None:
        return BackfillStatus.UNKNOWN
    if progress.heartbeat_age_seconds > stall_after.total_seconds():
        return BackfillStatus.STALLED
    return BackfillStatus.RUNNING


def read_checkpoint_progress(path: Path, *, now: datetime | None = None) -> BackfillProgress:
    """Read a checkpoint without changing it or contacting Airflow."""
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise ValueError("checkpoint must contain a JSON object")
    plan_data = payload.get("plan")
    if not isinstance(plan_data, dict):
        raise ValueError("checkpoint has no valid plan")

    try:
        plan = BackfillPlan(
            sources=tuple(plan_data["sources"]),
            start=date.fromisoformat(plan_data["start"]),
            end=date.fromisoformat(plan_data["end"]),
            interval_days=plan_data["interval_days"],
            nvd_mode=plan_data["nvd_mode"],
            chunk_days=plan_data["chunk_days"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("checkpoint has an invalid plan") from exc
    validate_plan(plan)

    completed = payload.get("completed_run_ids")
    if not isinstance(completed, list) or not all(isinstance(run_id, str) for run_id in completed):
        raise ValueError("checkpoint has invalid completed_run_ids")

    expected_run_ids = {backfill_run_id(plan, window) for window in plan.windows()}
    completed_run_ids = set(completed)
    if len(completed_run_ids) != len(completed) or not completed_run_ids <= expected_run_ids:
        raise ValueError("checkpoint has duplicate or unknown completed run IDs")

    active = _read_active(payload.get("active"), plan)
    if active is not None and active.run_id in completed_run_ids:
        raise ValueError("active run ID is already completed")

    updated_at = _read_updated_at(payload.get("updated_at"))
    if active is not None and updated_at is None:
        raise ValueError("active checkpoint has no updated_at timestamp")

    heartbeat_age_seconds = None
    if active is not None and updated_at is not None:
        current_time = now or datetime.now(UTC)
        if current_time.tzinfo is None:
            raise ValueError("current time must include a timezone")
        heartbeat_age_seconds = max(0, int((current_time - updated_at).total_seconds()))

    completed_windows = len(completed_run_ids)
    total_windows = len(expected_run_ids)
    return BackfillProgress(
        total_windows=total_windows,
        completed_windows=completed_windows,
        remaining_windows=total_windows - completed_windows,
        active=active,
        updated_at=updated_at,
        heartbeat_age_seconds=heartbeat_age_seconds,
    )


def _read_active(value: object, plan: BackfillPlan) -> ActiveBackfill | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("checkpoint has invalid active run data")
    try:
        active = ActiveBackfill(
            run_id=value["run_id"],
            start=date.fromisoformat(value["start"]),
            end=date.fromisoformat(value["end"]),
            state=value["state"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("checkpoint has invalid active run data") from exc
    if (
        not isinstance(active.run_id, str)
        or not active.run_id
        or not isinstance(active.state, str)
        or not active.state
    ):
        raise ValueError("checkpoint has invalid active run data")
    matching_windows = [
        window
        for window in plan.windows()
        if backfill_run_id(plan, window) == active.run_id
        and window.start == active.start
        and window.end == active.end
    ]
    if not matching_windows:
        raise ValueError("active run does not belong to the checkpoint plan")
    return active


def _read_updated_at(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("checkpoint has invalid updated_at timestamp")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("checkpoint has invalid updated_at timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("checkpoint updated_at timestamp must include a timezone")
    return timestamp


def _positive_minutes(value: str) -> float:
    try:
        minutes = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(minutes) or minutes <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite number")
    return minutes


def main(
    argv: list[str] | None = None,
    *,
    output: TextIO = sys.stdout,
    error: TextIO = sys.stderr,
) -> int:
    """Print checkpoint progress for a human operator."""
    parser = argparse.ArgumentParser(description="Show progress from a backfill checkpoint.")
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=Path("data/backfill-checkpoint.json"),
        help="path to the backfill checkpoint JSON file",
    )
    parser.add_argument(
        "--stall-after-minutes",
        type=_positive_minutes,
        default=30.0,
        help="classify an active run as stalled after this many minutes",
    )
    args = parser.parse_args(argv)

    try:
        progress = read_checkpoint_progress(args.checkpoint)
        status = classify_progress(
            progress,
            stall_after=timedelta(minutes=args.stall_after_minutes),
        )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=error)
        return 2

    print(f"Status: {status}", file=output)
    print(f"Total windows: {progress.total_windows}", file=output)
    print(f"Completed windows: {progress.completed_windows}", file=output)
    print(f"Remaining windows: {progress.remaining_windows}", file=output)
    if progress.active is None:
        print("Active window: none", file=output)
    else:
        print(f"Active window: {progress.active.start}..{progress.active.end}", file=output)
        print(f"Active state: {progress.active.state}", file=output)
        print(f"Active run ID: {progress.active.run_id}", file=output)
        print(f"Heartbeat age: {progress.heartbeat_age_seconds} seconds", file=output)
    if progress.updated_at is not None:
        print(f"Updated at: {progress.updated_at.isoformat()}", file=output)
    if status is BackfillStatus.FAILED:
        return 1
    if status in {BackfillStatus.STALLED, BackfillStatus.UNKNOWN}:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
