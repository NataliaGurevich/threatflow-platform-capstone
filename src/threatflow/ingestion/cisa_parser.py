"""Strict validation and transformation of CISA KEV JSON."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import date, datetime
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
    cwes: list[str] | None = None

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
    catalogVersion: str | None = None
    dateReleased: datetime | None = None

    @field_validator("dateReleased", mode="before")
    @classmethod
    def parse_release_datetime(cls, value: Any) -> datetime | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("dateReleased must be an ISO timestamp string")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("dateReleased must be a valid ISO timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("dateReleased must include a timezone")
        return parsed


@dataclass(frozen=True)
class ParsedCatalog:
    """Validated CISA document including catalog-level lineage metadata."""

    catalog_version: str | None
    date_released: datetime | None
    declared_count: int | None
    records: tuple[dict[str, Any], ...]


def parse_catalog_document(content: bytes) -> ParsedCatalog:
    try:
        value = json.loads(content)
        catalog = Catalog.model_validate(value)
    except (json.JSONDecodeError, UnicodeDecodeError, ValidationError, TypeError) as exc:
        raise ValueError(f"invalid CISA KEV catalog: {exc}") from exc
    if not catalog.vulnerabilities:
        raise ValueError("CISA KEV catalog is empty")
    if catalog.count is not None and catalog.count != len(catalog.vulnerabilities):
        raise ValueError("CISA KEV catalog count does not match vulnerabilities")
    cve_ids = [record.cveID for record in catalog.vulnerabilities]
    if len(cve_ids) != len(set(cve_ids)):
        raise ValueError("CISA KEV catalog contains duplicate CVE identifiers")
    records = tuple(
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
            "cwes": tuple(r.cwes) if r.cwes is not None else None,
        }
        for r in catalog.vulnerabilities
    )
    return ParsedCatalog(
        catalog_version=catalog.catalogVersion,
        date_released=catalog.dateReleased,
        declared_count=catalog.count,
        records=records,
    )


def parse_catalog(content: bytes) -> list[dict[str, Any]]:
    """Return the existing PostgreSQL projection for backward compatibility."""
    records = parse_catalog_document(content).records
    return [{key: value for key, value in record.items() if key != "cwes"} for record in records]
