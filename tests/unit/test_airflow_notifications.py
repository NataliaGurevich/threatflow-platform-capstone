import json
import logging
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from threatflow.orchestration.airflow_notifications import (
    TOPIC_ARN_ENV,
    notify_task_failure,
    publish_task_failure,
)

TOPIC_ARN = "arn:aws:sns:eu-central-1:123456789012:threatflow-alerts"


class RecordingSns:
    def __init__(self):
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "message-1"}


def context():
    return {
        "task_instance": SimpleNamespace(
            dag_id="cisa_daily",
            task_id="ingest_cisa",
            try_number=4,
            max_tries=3,
            log_url="http://airflow:8080/task-log",
        ),
        "run_id": "scheduled__2026-11-25T04:00:00+00:00",
        "logical_date": datetime(2026, 11, 25, 4, tzinfo=UTC),
        "exception": ValueError("catalog validation failed\nraw payload omitted"),
    }


def test_publishes_one_bounded_structured_failure():
    client = RecordingSns()

    publish_task_failure(context(), topic_arn=TOPIC_ARN, client=client)

    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["TopicArn"] == TOPIC_ARN
    assert call["Subject"] == "ThreatFlow Airflow failed: cisa_daily.ingest_cisa"
    payload = json.loads(call["Message"])
    assert payload["event"] == "airflow_task_failed"
    assert payload["try_number"] == 4
    assert payload["exception_type"] == "ValueError"
    assert payload["exception"] == "catalog validation failed raw payload omitted"


def test_missing_topic_skips_without_creating_aws_client(monkeypatch, caplog):
    monkeypatch.delenv(TOPIC_ARN_ENV, raising=False)
    monkeypatch.setattr(
        "threatflow.orchestration.airflow_notifications.boto3.client",
        lambda *args, **kwargs: pytest.fail("AWS client must not be created"),
    )

    with caplog.at_level(logging.WARNING):
        notify_task_failure(context())

    assert "status=skipped reason=topic_not_configured" in caplog.text


def test_invalid_topic_arn_fails_before_aws_call(monkeypatch):
    monkeypatch.setenv(TOPIC_ARN_ENV, "not-an-arn")
    monkeypatch.setattr(
        "threatflow.orchestration.airflow_notifications.boto3.client",
        lambda *args, **kwargs: pytest.fail("AWS client must not be created"),
    )

    with pytest.raises(ValueError, match="valid SNS ARN"):
        notify_task_failure(context())
