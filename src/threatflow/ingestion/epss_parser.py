"""Strict validation and projection of EPSS gzip CSV files."""

import csv
import gzip
import re
from datetime import date

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def parse_dataset(content: bytes, score_date: date) -> list[dict]:
    try:
        text = gzip.decompress(content).decode("utf-8-sig")
    except (OSError, EOFError, UnicodeDecodeError) as exc:
        raise ValueError("invalid or truncated EPSS gzip CSV") from exc
    source_lines = text.splitlines()
    if source_lines and source_lines[0].startswith("#"):
        match = re.search(r"score_date:(\d{4}-\d{2}-\d{2})", source_lines[0])
        if match and date.fromisoformat(match.group(1)) != score_date:
            raise ValueError("EPSS source score_date does not match requested date")
    lines = [line for line in source_lines if not line.startswith("#")]
    if not lines:
        raise ValueError("empty EPSS dataset")
    reader = csv.DictReader(lines)
    if not reader.fieldnames or not {"cve", "epss", "percentile"}.issubset(reader.fieldnames):
        raise ValueError("EPSS CSV missing required columns")
    result, seen = [], set()
    for row in reader:
        cve = row.get("cve", "")
        if not _CVE.fullmatch(cve):
            raise ValueError(f"invalid CVE identifier: {cve!r}")
        if cve in seen:
            raise ValueError(f"duplicate CVE: {cve}")
        seen.add(cve)
        try:
            epss, percentile = float(row["epss"]), float(row["percentile"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid score for {cve}") from exc
        if not 0 <= epss <= 1 or not 0 <= percentile <= 1:
            raise ValueError(f"score out of range for {cve}")
        result.append(
            {"cve_id": cve, "score_date": score_date, "epss_score": epss, "percentile": percentile}
        )
    if not result:
        raise ValueError("EPSS dataset has no records")
    return result
