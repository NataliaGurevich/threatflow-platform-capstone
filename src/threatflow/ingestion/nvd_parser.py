"""Validation and projection of NVD CVE API 2.0 records."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from threatflow.ingestion.schema_observability import log_source_schema

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_METRIC_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
_METRIC_VERSIONS = dict(zip(_METRIC_KEYS, ("4.0", "3.1", "3.0", "2.0"), strict=True))
LOGGER = logging.getLogger(__name__)

_RESPONSE_REQUIRED_FIELDS = {"startIndex", "resultsPerPage", "totalResults", "vulnerabilities"}
_RESPONSE_OPTIONAL_FIELDS = {"format", "version", "timestamp"}
_CVE_REQUIRED_FIELDS = {"id", "published", "lastModified", "descriptions"}
_CVE_OPTIONAL_FIELDS = {
    "sourceIdentifier",
    "vulnStatus",
    "cveTags",
    "metrics",
    "weaknesses",
    "configurations",
    "references",
    "evaluatorComment",
}
_PROJECTED_FIELDS = {
    "cve_id",
    "description",
    "published",
    "last_modified",
    "cvss_version",
    "cvss_score",
    "cvss_severity",
    "cvss_vector",
    "cwe_ids",
    "references",
}


def _date(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid {field}") from exc
    # NVD API 2.0 emits response timestamps without an offset (for example,
    # 2023-01-10T19:46:53.290) while its date parameters and service operate
    # in UTC. Attach UTC only for this documented NVD response shape.
    if parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _best_metric(metrics: dict[str, Any]) -> dict[str, Any] | None:
    for key in _METRIC_KEYS:
        candidates = metrics.get(key) or []
        valid = []
        for item in candidates:
            data = item.get("cvssData") if isinstance(item, dict) else None
            score = data.get("baseScore") if isinstance(data, dict) else None
            vector = data.get("vectorString") if isinstance(data, dict) else None
            severity = item.get("baseSeverity") or (data.get("baseSeverity") if data else None)
            if isinstance(score, (int, float)) and not isinstance(score, bool) and vector:
                valid.append(
                    (
                        item.get("type") != "PRIMARY",
                        float(score),
                        str(severity) if severity else None,
                        str(vector),
                    )
                )
        if valid:
            _, score, severity, vector = sorted(
                valid, key=lambda metric: (metric[0], -metric[1], metric[3])
            )[0]
            return {
                "version": _METRIC_VERSIONS[key],
                "score": score,
                "severity": severity,
                "vector": vector,
            }
    return None


def parse_response(content: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid NVD JSON: {exc}") from exc
    log_source_schema(
        LOGGER,
        source="nvd",
        scope="response",
        actual_fields=data.keys() if isinstance(data, dict) else (),
        required_fields=_RESPONSE_REQUIRED_FIELDS,
        optional_fields=_RESPONSE_OPTIONAL_FIELDS,
    )
    if not isinstance(data, dict) or not all(
        k in data for k in ("startIndex", "resultsPerPage", "totalResults", "vulnerabilities")
    ):
        raise ValueError("invalid NVD response structure")
    if any(
        type(data[k]) is not int or data[k] < 0
        for k in ("startIndex", "resultsPerPage", "totalResults")
    ):
        raise ValueError("invalid NVD pagination values")
    if not isinstance(data["vulnerabilities"], list):
        raise ValueError("vulnerabilities must be a list")
    cve_fields = {
        field
        for entry in data["vulnerabilities"]
        if isinstance(entry, dict) and isinstance(entry.get("cve"), dict)
        for field in entry["cve"]
    }
    log_source_schema(
        LOGGER,
        source="nvd",
        scope="cve",
        actual_fields=cve_fields,
        required_fields=_CVE_REQUIRED_FIELDS,
        optional_fields=_CVE_OPTIONAL_FIELDS,
        projected_fields=_PROJECTED_FIELDS,
    )
    records = []
    for entry in data["vulnerabilities"]:
        cve = entry.get("cve") if isinstance(entry, dict) else None
        if not isinstance(cve, dict):
            raise ValueError("vulnerability missing CVE object")
        cve_id = cve.get("id")
        if not isinstance(cve_id, str) or not _CVE.fullmatch(cve_id):
            raise ValueError(f"invalid CVE identifier: {cve_id!r}")
        published = _date(cve.get("published"), "published")
        modified = _date(cve.get("lastModified"), "lastModified")
        descriptions = cve.get("descriptions")
        if not isinstance(descriptions, list) or not descriptions:
            raise ValueError(f"{cve_id} missing descriptions")
        english = [
            d.get("value")
            for d in descriptions
            if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str)
        ]
        description = (
            english[0]
            if english
            else next(
                (
                    d.get("value")
                    for d in descriptions
                    if isinstance(d, dict) and isinstance(d.get("value"), str)
                ),
                None,
            )
        )
        if description is None:
            raise ValueError(f"{cve_id} has no valid description")
        weaknesses = cve.get("weaknesses") or []
        cwe_ids = sorted(
            {
                d["value"]
                for w in weaknesses
                if isinstance(w, dict)
                for d in w.get("description", [])
                if isinstance(d, dict)
                and isinstance(d.get("value"), str)
                and d["value"].startswith("CWE-")
            }
        )
        refs = cve.get("references") or []
        if not isinstance(refs, list):
            raise ValueError(f"{cve_id} references must be a list")
        metrics = cve.get("metrics") or {}
        if not isinstance(metrics, dict):
            raise ValueError(f"{cve_id} metrics must be an object")
        metric = _best_metric(metrics)
        records.append(
            {
                "cve_id": cve_id,
                "description": description,
                "published": published,
                "last_modified": modified,
                "cvss_version": metric["version"] if metric else None,
                "cvss_score": metric["score"] if metric else None,
                "cvss_severity": metric["severity"] if metric else None,
                "cvss_vector": metric["vector"] if metric else None,
                "cwe_ids": cwe_ids or None,
                "references": refs or None,
            }
        )
    return {k: data[k] for k in ("startIndex", "resultsPerPage", "totalResults")}, records
