"""Pure EPSS dataset completeness rules shared by local and AWS runtimes."""

from datetime import date

# Conservative floors by dataset era. The published gzip header has model_version and
# score_date, but no row count. Revisit these floors as the CVE corpus grows.
MIN_ROWS_BY_YEAR = {
    2021: 50_000,
    2022: 75_000,
    2023: 100_000,
    2024: 130_000,
    2025: 160_000,
    2026: 180_000,
}


def validate_completeness(
    count: int,
    score_date: date,
    adjacent_count: int | None = None,
    minimum_count_override: int | None = None,
) -> None:
    """Reject structurally valid EPSS archives that are implausibly incomplete."""
    if minimum_count_override is not None and (
        type(minimum_count_override) is not int or minimum_count_override < 1
    ):
        raise ValueError("EPSS completeness override must be a positive integer")
    floor = minimum_count_override or MIN_ROWS_BY_YEAR.get(
        score_date.year, MIN_ROWS_BY_YEAR[max(MIN_ROWS_BY_YEAR)]
    )
    adjacent_failed = (
        minimum_count_override is None
        and adjacent_count is not None
        and count < adjacent_count * 0.8
    )
    if count < floor or adjacent_failed:
        raise ValueError(
            f"EPSS dataset incomplete for {score_date}: {count} rows; "
            f"minimum {floor}, adjacent day {adjacent_count}"
        )
