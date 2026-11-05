"""Submit long historical ranges as sequential bounded Airflow DAG runs."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import TextIO

import httpx

from threatflow.orchestration.date_windows import date_chunks

DAG_ID = "threat_intel_backfill"


@dataclass(frozen=True)
class BackfillWindow:
    start: date
    end: date


@dataclass(frozen=True)
class BackfillPlan:
    sources: tuple[str, ...]
    start: date
    end: date
    interval_days: int
    nvd_mode: str
    chunk_days: int

    def windows(self) -> list[BackfillWindow]:
        return [
            BackfillWindow(first, last)
            for first, last in date_chunks(self.start, self.end, self.interval_days)
        ]

    def identity(self) -> str:
        payload = json.dumps(self.serializable(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def serializable(self) -> dict[str, object]:
        return {
            "sources": list(self.sources),
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "interval_days": self.interval_days,
            "nvd_mode": self.nvd_mode,
            "chunk_days": self.chunk_days,
        }


class AirflowClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        timeout: float = 30,
        client: httpx.Client | None = None,
    ):
        self._username = username
        self._password = password
        self._client = client or httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._owns_client = client is None
        self._authenticate()

    def _authenticate(self) -> None:
        response = self._client.post(
            "/auth/token", json={"username": self._username, "password": self._password}
        )
        response.raise_for_status()
        self._client.headers["Authorization"] = f"Bearer {response.json()['access_token']}"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def trigger(self, run_id: str, configuration: dict[str, object]) -> None:
        response = self._client.post(
            f"/api/v2/dags/{DAG_ID}/dagRuns",
            json={"dag_run_id": run_id, "logical_date": None, "conf": configuration},
        )
        if response.status_code == httpx.codes.CONFLICT:
            self.state(run_id)
            return
        response.raise_for_status()

    def state(self, run_id: str) -> str:
        response = self._client.get(f"/api/v2/dags/{DAG_ID}/dagRuns/{run_id}")
        response.raise_for_status()
        return str(response.json()["state"]).lower()


def validate_plan(plan: BackfillPlan) -> None:
    if not plan.sources or set(plan.sources) - {"nvd", "cisa", "epss"}:
        raise ValueError("sources must contain nvd, cisa, and/or epss")
    if len(set(plan.sources)) != len(plan.sources):
        raise ValueError("sources must be unique")
    if plan.start > plan.end:
        raise ValueError("start date must not be after end date")
    maximum_interval_days = 366 if set(plan.sources) == {"cisa"} else 31
    if not 1 <= plan.interval_days <= maximum_interval_days:
        raise ValueError(f"interval-days must be between 1 and {maximum_interval_days}")
    if not 1 <= plan.chunk_days <= 31:
        raise ValueError("chunk-days must be between 1 and 31")
    if plan.nvd_mode not in {"published", "modified"}:
        raise ValueError("nvd-mode must be published or modified")
    if "epss" in plan.sources and plan.start < date(2021, 4, 14):
        raise ValueError("EPSS archive starts on 2021-04-14")


def backfill_run_id(plan: BackfillPlan, window: BackfillWindow) -> str:
    return f"range-{plan.identity()}-{window.start:%Y%m%d}-{window.end:%Y%m%d}"


def _read_checkpoint(path: Path, plan: BackfillPlan) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text())
    if data.get("plan") != plan.serializable():
        raise ValueError(f"checkpoint {path} belongs to a different backfill plan")
    return set(data.get("completed_run_ids", []))


def _write_checkpoint(
    path: Path,
    plan: BackfillPlan,
    completed: set[str],
    *,
    active_run_id: str | None = None,
    active_window: BackfillWindow | None = None,
    active_state: str | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    payload: dict[str, object] = {
        "plan": plan.serializable(),
        "completed_run_ids": sorted(completed),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    if active_run_id is not None and active_window is not None and active_state is not None:
        payload["active"] = {
            "run_id": active_run_id,
            "start": active_window.start.isoformat(),
            "end": active_window.end.isoformat(),
            "state": active_state,
        }
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(path)


def execute_plan(
    plan: BackfillPlan,
    airflow: AirflowClient,
    checkpoint: Path,
    *,
    poll_seconds: float = 15,
    run_timeout_seconds: float = 12 * 60 * 60,
    output: TextIO,
) -> None:
    validate_plan(plan)
    lock_path = checkpoint.with_suffix(checkpoint.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(f"another controller is using {checkpoint}") from exc
        completed = _read_checkpoint(checkpoint, plan)
        windows = plan.windows()
        for number, window in enumerate(windows, start=1):
            run_id = backfill_run_id(plan, window)
            if run_id in completed:
                print(
                    f"[{number}/{len(windows)}] already complete {window.start}..{window.end}",
                    file=output,
                )
                continue
            configuration = {
                "sources": list(plan.sources),
                "start_date": window.start.isoformat(),
                "end_date": window.end.isoformat(),
                "nvd_mode": plan.nvd_mode,
                "chunk_days": plan.chunk_days,
            }
            print(f"[{number}/{len(windows)}] trigger {window.start}..{window.end}", file=output)
            _write_checkpoint(
                checkpoint,
                plan,
                completed,
                active_run_id=run_id,
                active_window=window,
                active_state="submitting",
            )
            airflow.trigger(run_id, configuration)
            deadline = time.monotonic() + run_timeout_seconds
            while True:
                state = airflow.state(run_id)
                if state == "success":
                    completed.add(run_id)
                    _write_checkpoint(checkpoint, plan, completed)
                    break
                _write_checkpoint(
                    checkpoint,
                    plan,
                    completed,
                    active_run_id=run_id,
                    active_window=window,
                    active_state=state,
                )
                if state == "failed":
                    raise RuntimeError(f"Airflow run {run_id} finished with state={state}")
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Airflow run {run_id} did not finish before timeout")
                time.sleep(poll_seconds)
            print(f"[{number}/{len(windows)}] success {window.start}..{window.end}", file=output)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a long NVD/CISA/EPSS backfill as sequential bounded Airflow runs."
    )
    parser.add_argument("--sources", nargs="+", required=True, choices=("nvd", "cisa", "epss"))
    parser.add_argument("--start", required=True, type=date.fromisoformat)
    parser.add_argument("--end", required=True, type=date.fromisoformat)
    parser.add_argument("--interval-days", type=int, default=31)
    parser.add_argument("--chunk-days", type=int, default=7)
    parser.add_argument("--nvd-mode", choices=("published", "modified"), default="published")
    parser.add_argument(
        "--airflow-url",
        default=os.getenv("THREATFLOW_AIRFLOW_URL", "http://localhost:8080"),
    )
    parser.add_argument("--username", default=os.getenv("AIRFLOW_ADMIN_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("AIRFLOW_ADMIN_PASSWORD"))
    parser.add_argument("--checkpoint", type=Path, default=Path("data/backfill-checkpoint.json"))
    parser.add_argument("--poll-seconds", type=float, default=15)
    parser.add_argument("--run-timeout-hours", type=float, default=12)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    plan = BackfillPlan(
        sources=tuple(args.sources),
        start=args.start,
        end=args.end,
        interval_days=args.interval_days,
        nvd_mode=args.nvd_mode,
        chunk_days=args.chunk_days,
    )
    try:
        validate_plan(plan)
    except ValueError as exc:
        parser.error(str(exc))
    if args.dry_run:
        print(
            json.dumps(
                {
                    "plan_id": plan.identity(),
                    "windows": [
                        {"start": window.start.isoformat(), "end": window.end.isoformat()}
                        for window in plan.windows()
                    ],
                },
                indent=2,
            )
        )
        return
    if not args.password:
        parser.error("--password or AIRFLOW_ADMIN_PASSWORD is required unless --dry-run is used")
    airflow = AirflowClient(args.airflow_url, args.username, args.password)
    try:
        execute_plan(
            plan,
            airflow,
            args.checkpoint,
            poll_seconds=args.poll_seconds,
            run_timeout_seconds=args.run_timeout_hours * 60 * 60,
            output=sys.stdout,
        )
    finally:
        airflow.close()


if __name__ == "__main__":
    main()
