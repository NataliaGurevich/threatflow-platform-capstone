"""One bounded SNS notification for a terminal Airflow task failure."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from typing import Any

import boto3
from botocore.config import Config

LOGGER = logging.getLogger(__name__)
TOPIC_ARN_ENV = "THREATFLOW_AIRFLOW_FAILURE_TOPIC_ARN"
_BOTO_CONFIG = Config(
    retries={"total_max_attempts": 3, "mode": "adaptive"},
    connect_timeout=5,
    read_timeout=10,
)


def notify_task_failure(context: Mapping[str, Any]) -> None:
    """Airflow callback: publish one notification after a task reaches FAILED."""
    topic_arn = os.getenv(TOPIC_ARN_ENV, "").strip()
    if not topic_arn:
        LOGGER.warning(
            "stage=task_failure_notification status=skipped reason=topic_not_configured"
        )
        return
    region = _region_from_topic_arn(topic_arn)
    client = boto3.client("sns", region_name=region, config=_BOTO_CONFIG)
    publish_task_failure(context, topic_arn=topic_arn, client=client)


def publish_task_failure(
    context: Mapping[str, Any], *, topic_arn: str, client: Any
) -> None:
    """Publish a compact failure envelope using an injected SNS client."""
    payload = _failure_payload(context)
    client.publish(
        TopicArn=topic_arn,
        Subject=_subject(payload["dag_id"], payload["task_id"]),
        Message=json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str),
    )
    LOGGER.info(
        "stage=task_failure_notification status=published dag_id=%s task_id=%s run_id=%s",
        payload["dag_id"],
        payload["task_id"],
        payload["run_id"],
    )


def _failure_payload(context: Mapping[str, Any]) -> dict[str, Any]:
    task_instance = context.get("task_instance") or context.get("ti")
    dag_run = context.get("dag_run")
    exception = context.get("exception")
    return {
        "event": "airflow_task_failed",
        "dag_id": _attribute(task_instance, "dag_id", "unknown"),
        "task_id": _attribute(task_instance, "task_id", "unknown"),
        "run_id": context.get("run_id") or _attribute(dag_run, "run_id", "unknown"),
        "try_number": _attribute(task_instance, "try_number", None),
        "max_tries": _attribute(task_instance, "max_tries", None),
        "logical_date": context.get("logical_date"),
        "exception_type": type(exception).__name__ if exception is not None else "Unknown",
        "exception": _bounded_text(exception, 1000),
        "log_url": _attribute(task_instance, "log_url", None),
    }


def _attribute(value: Any, name: str, default: Any) -> Any:
    return getattr(value, name, default) if value is not None else default


def _bounded_text(value: Any, limit: int) -> str:
    text = " ".join(str(value or "unknown").split())
    return text[:limit]


def _subject(dag_id: str, task_id: str) -> str:
    return _bounded_text(f"ThreatFlow Airflow failed: {dag_id}.{task_id}", 100)


def _region_from_topic_arn(topic_arn: str) -> str:
    parts = topic_arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] != "sns" or not parts[3]:
        raise ValueError("Airflow failure topic must be a valid SNS ARN")
    return parts[3]
