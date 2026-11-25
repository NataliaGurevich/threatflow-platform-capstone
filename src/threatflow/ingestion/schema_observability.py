"""Compact source-schema observations for ingestion and Airflow logs."""

from __future__ import annotations

import logging
from collections.abc import Iterable


def log_source_schema(
    logger: logging.Logger,
    *,
    source: str,
    scope: str,
    actual_fields: Iterable[str],
    required_fields: Iterable[str],
    optional_fields: Iterable[str] = (),
    projected_fields: Iterable[str] = (),
) -> None:
    """Log a bounded schema comparison without logging source records or values."""
    actual = frozenset(actual_fields)
    required = frozenset(required_fields)
    optional = frozenset(optional_fields)
    projected = frozenset(projected_fields)
    missing_required = required - actual
    missing_optional = optional - actual
    unexpected = actual - required - optional
    if missing_required:
        status = "rejected"
        action = "reject"
        log = logger.error
    elif unexpected:
        status = "accepted_with_drift"
        action = "accept_known_projection"
        log = logger.warning
    else:
        status = "accepted"
        action = "accept"
        log = logger.info
    log(
        "stage=source_schema source=%s scope=%s status=%s "
        "action=%s "
        "actual_fields=%s required_fields=%s optional_fields=%s "
        "missing_required_fields=%s missing_optional_fields=%s "
        "unexpected_fields=%s projected_fields=%s",
        source,
        scope,
        status,
        action,
        _format_fields(actual),
        _format_fields(required),
        _format_fields(optional),
        _format_fields(missing_required),
        _format_fields(missing_optional),
        _format_fields(unexpected),
        _format_fields(projected),
    )


def _format_fields(fields: Iterable[str]) -> str:
    ordered = sorted(fields)
    return ",".join(ordered) if ordered else "-"
