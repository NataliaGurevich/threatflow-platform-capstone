"""Structured audit events shared by Bronze-to-Silver Lambda adapters."""

from __future__ import annotations

import json
import logging
from typing import Any


def emit_pipeline_event(
    logger: logging.Logger,
    *,
    event: str,
    source: str,
    source_sha256: str,
    bronze_bucket: str,
    bronze_key: str,
    bronze_version_id: str,
    **details: Any,
) -> None:
    """Write one compact, queryable JSON event without high-cardinality metrics."""
    payload = {
        "event_type": "pipeline_event",
        "event": event,
        "source": source,
        "source_sha256": source_sha256,
        "bronze_bucket": bronze_bucket,
        "bronze_key": bronze_key,
        "bronze_version_id": bronze_version_id,
        **details,
    }
    logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str))
