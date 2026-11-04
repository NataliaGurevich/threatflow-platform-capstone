"""Strict validation and transformation of CISA KEV JSON."""

from __future__ import annotations

import json
import re
from datetime import date
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    cveID: str
    vendorProject: str
    product: str
    vulnerabilityName: str
    dateAdded: date
    shortDescription: str
    requiredAction: str
    dueDate: date
    knownRansomwareCampaignUse: str
    notes: str | None = None

    @field_validator("dateAdded", "dueDate", mode="before")
    @classmethod
    def parse_iso_date(cls, value: Any) -> date:
        if not isinstance(value, str):
            raise ValueError("date must be an ISO YYYY-MM-DD string")
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("date must be a valid ISO YYYY-MM-DD date") from exc

    @field_validator("cveID")
    @classmethod
    def valid_cve(cls, value: str) -> str:
        if not _CVE.fullmatch(value):
            raise ValueError("invalid CVE identifier")
        return value


class Catalog(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    vulnerabilities: list[Vulnerability]
    count: int | None = None


def parse_catalog(content: bytes) -> list[dict[str, Any]]:
    try:
        value = json.loads(content)
        catalog = Catalog.model_validate(value)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError) as exc:
        raise ValueError(f"invalid CISA KEV catalog: {exc}") from exc
    if not catalog.vulnerabilities:
        raise ValueError("CISA KEV catalog is empty")
    if catalog.count is not None and catalog.count != len(catalog.vulnerabilities):
        raise ValueError("CISA KEV catalog count does not match vulnerabilities")
    return [
        {
            "cve_id": r.cveID,
            "vendor_project": r.vendorProject,
            "product": r.product,
            "vulnerability_name": r.vulnerabilityName,
            "date_added": r.dateAdded,
            "short_description": r.shortDescription,
            "required_action": r.requiredAction,
            "due_date": r.dueDate,
            "known_ransomware_campaign_use": r.knownRansomwareCampaignUse,
            "notes": r.notes,
        }
        for r in catalog.vulnerabilities
    ]
