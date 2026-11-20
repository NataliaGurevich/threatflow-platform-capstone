-- Data Quality & Reliability: missing EPSS daily summaries.
-- This is a single read-only SELECT suitable for a Metabase table card.
-- Freshness handles trailing unpublished dates; this query finds gaps inside
-- the latest 90-day interval already covered by ThreatFlow.

WITH settings AS (
    SELECT 90 AS history_days
),
coverage AS (
    SELECT max(score_date) AS latest_score_date
    FROM epss_daily_summaries
),
expected_range AS (
    SELECT
        greatest(
            coverage.latest_score_date - (settings.history_days - 1),
            date '2021-04-14'
        ) AS expected_start_date,
        coverage.latest_score_date AS expected_end_date
    FROM coverage
    CROSS JOIN settings
),
expected_dates AS (
    SELECT generated_date::date AS score_date
    FROM expected_range
    CROSS JOIN LATERAL generate_series(
        expected_start_date,
        expected_end_date,
        interval '1 day'
    ) AS generated_date
),
missing_dates AS (
    SELECT expected.score_date AS missing_date
    FROM expected_dates AS expected
    LEFT JOIN epss_daily_summaries AS actual USING (score_date)
    WHERE actual.score_date IS NULL
),
missing_summary AS (
    SELECT count(*) AS missing_date_count
    FROM missing_dates
)
SELECT
    CASE
        WHEN expected_range.expected_end_date IS NULL THEN 'CRITICAL'
        WHEN missing_summary.missing_date_count = 0 THEN 'OK'
        ELSE 'CRITICAL'
    END AS "Status",
    missing_summary.missing_date_count AS "Missing dates",
    missing_dates.missing_date AS "Missing score date",
    expected_range.expected_start_date AS "Checked from",
    expected_range.expected_end_date AS "Checked through"
FROM expected_range
CROSS JOIN missing_summary
LEFT JOIN missing_dates ON true
ORDER BY missing_dates.missing_date;
