"""Strict validation and projection of EPSS gzip CSV files."""

import csv
import gzip
import re
from bisect import bisect_right
from datetime import date

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SCORE_DATE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


def extract_score_date(content: bytes) -> date:
    """Return the authoritative score date embedded in an EPSS gzip header."""
    try:
        first_line = gzip.decompress(content).decode("utf-8-sig").splitlines()[0]
    except (OSError, EOFError, UnicodeDecodeError, IndexError) as exc:
        raise ValueError("cannot establish EPSS score date from source metadata") from exc
    match = _SCORE_DATE.search(first_line)
    if not first_line.startswith("#") or match is None:
        raise ValueError("EPSS source has no authoritative score_date metadata")
    return date.fromisoformat(match.group(1))


def parse_dataset(content: bytes, score_date: date) -> list[dict]:
    try:
        text = gzip.decompress(content).decode("utf-8-sig")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError("invalid or truncated EPSS gzip CSV") from exc
    source_lines = text.splitlines()
    if source_lines and source_lines[0].startswith("#"):
        match = _SCORE_DATE.search(source_lines[0])
        if match and date.fromisoformat(match.group(1)) != score_date:
            raise ValueError("EPSS source score_date does not match requested date")
        source_lines = source_lines[1:]
    lines = source_lines
    if not lines:
        raise ValueError("empty EPSS dataset")
    reader = csv.DictReader(lines)
    if not reader.fieldnames or not {"cve", "epss"}.issubset(reader.fieldnames):
        raise ValueError("EPSS CSV missing required columns")
    if len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError("EPSS CSV has duplicate columns")
    has_percentile = "percentile" in reader.fieldnames
    result, seen = [], set()
    for row in reader:
        if None in row or any(value is None for value in row.values()):
            raise ValueError("EPSS CSV row has incorrect number of fields")
        cve = row.get("cve", "")
        if not _CVE.fullmatch(cve):
            raise ValueError(f"invalid CVE identifier: {cve!r}")
        if cve in seen:
            raise ValueError(f"duplicate CVE: {cve}")
        seen.add(cve)
        try:
            epss = float(row["epss"])
            percentile = float(row["percentile"]) if has_percentile else None
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid score for {cve}") from exc
        if not 0 <= epss <= 1 or percentile is not None and not 0 <= percentile <= 1:
            raise ValueError(f"score out of range for {cve}")
        result.append(
            {"cve_id": cve, "score_date": score_date, "epss_score": epss, "percentile": percentile}
        )
    if not result:
        raise ValueError("EPSS dataset has no records")
    if not has_percentile:
        ordered_scores = sorted(row["epss_score"] for row in result)
        total = len(ordered_scores)
        for row in result:
            row["percentile"] = bisect_right(ordered_scores, row["epss_score"]) / total
    return result
