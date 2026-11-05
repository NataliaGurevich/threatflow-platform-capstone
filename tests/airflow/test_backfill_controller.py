import io
import json
from datetime import date

import httpx
import pytest

from threatflow.orchestration.backfill_controller import (
    AirflowClient,
    BackfillPlan,
    execute_plan,
    validate_plan,
)


class FakeAirflow:
    def __init__(self, states=None):
        self.states = iter(states or ["success"])
        self.triggered = []

    def trigger(self, run_id, configuration):
        self.triggered.append((run_id, configuration))

    def state(self, run_id):
        return next(self.states)


def plan(**overrides):
    values = {
        "sources": ("nvd", "epss"),
        "start": date(2026, 1, 1),
        "end": date(2026, 3, 3),
        "interval_days": 31,
        "nvd_mode": "modified",
        "chunk_days": 7,
    }
    values.update(overrides)
    return BackfillPlan(**values)


def test_plan_splits_into_inclusive_windows():
    assert [(window.start, window.end) for window in plan().windows()] == [
        (date(2026, 1, 1), date(2026, 1, 31)),
        (date(2026, 2, 1), date(2026, 3, 3)),
    ]


def test_airflow_client_uses_airflow_3_trigger_contract():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "token"})
        return httpx.Response(200, json={"state": "queued"})

    http = httpx.Client(base_url="http://airflow.test", transport=httpx.MockTransport(handler))
    airflow = AirflowClient("http://airflow.test", "admin", "secret", client=http)
    airflow.trigger("range-test", {"sources": ["epss"]})

    assert requests[1].headers["Authorization"] == "Bearer token"
    assert json.loads(requests[1].content) == {
        "dag_run_id": "range-test",
        "logical_date": None,
        "conf": {"sources": ["epss"]},
    }


@pytest.mark.parametrize(
    "candidate",
    [
        plan(sources=("bad",)),
        plan(start=date(2026, 2, 1), end=date(2026, 1, 1)),
        plan(interval_days=32),
        plan(sources=("epss",), start=date(2021, 4, 13)),
    ],
)
def test_invalid_plans(candidate):
    with pytest.raises(ValueError):
        validate_plan(candidate)


def test_execute_is_sequential_and_resumes(tmp_path, monkeypatch):
    monkeypatch.setattr("threatflow.orchestration.backfill_controller.time.sleep", lambda _: None)
    checkpoint = tmp_path / "checkpoint.json"
    airflow = FakeAirflow(["running", "success", "success"])

    execute_plan(plan(), airflow, checkpoint, poll_seconds=0, output=io.StringIO())

    assert len(airflow.triggered) == 2
    assert airflow.triggered[0][1]["start_date"] == "2026-01-01"
    assert airflow.triggered[1][1]["end_date"] == "2026-03-03"
    saved_checkpoint = json.loads(checkpoint.read_text())
    assert len(saved_checkpoint["completed_run_ids"]) == 2
    assert "active" not in saved_checkpoint
    assert saved_checkpoint["updated_at"].endswith("+00:00")

    resumed = FakeAirflow()
    execute_plan(plan(), resumed, checkpoint, poll_seconds=0, output=io.StringIO())
    assert resumed.triggered == []


def test_failure_stops_before_next_window(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    airflow = FakeAirflow(["failed"])
    with pytest.raises(RuntimeError, match="state=failed"):
        execute_plan(plan(), airflow, checkpoint, output=io.StringIO())
    assert len(airflow.triggered) == 1
    saved_checkpoint = json.loads(checkpoint.read_text())
    assert saved_checkpoint["active"]["state"] == "failed"
    assert saved_checkpoint["completed_run_ids"] == []


def test_checkpoint_cannot_be_reused_for_different_plan(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    execute_plan(plan(end=date(2026, 1, 1)), FakeAirflow(), checkpoint, output=io.StringIO())
    with pytest.raises(ValueError, match="different backfill plan"):
        execute_plan(plan(end=date(2026, 1, 2)), FakeAirflow(), checkpoint, output=io.StringIO())


def test_cisa_is_a_supported_source():
    validate_plan(plan(sources=("cisa",)))
    validate_plan(plan(sources=("cisa",), interval_days=366))
    with pytest.raises(ValueError, match="31"):
        validate_plan(plan(sources=("cisa", "epss"), interval_days=366))
