-- Data Quality & Reliability: missing EPSS dates KPI.
-- This is a single read-only SELECT returning one numeric value for a
-- Metabase scalar card. It counts internal gaps in the latest 90 covered dates.

WITH coverage AS (
    SELECT max(score_date) AS latest_score_date
    FROM epss_daily_summaries
),
expected_dates AS (
    SELECT generated_date::date AS score_date
    FROM coverage
    CROSS JOIN LATERAL generate_series(
        greatest(latest_score_date - 89, date '2021-04-14'),
        latest_score_date,
        interval '1 day'
    ) AS generated_date
),
missing_dates AS (
    SELECT count(*) AS missing_date_count
    FROM expected_dates AS expected
    LEFT JOIN epss_daily_summaries AS actual USING (score_date)
    WHERE actual.score_date IS NULL
)
SELECT
    CASE
        WHEN coverage.latest_score_date IS NULL THEN NULL
        ELSE missing_dates.missing_date_count
    END AS "Missing EPSS dates"
FROM coverage
CROSS JOIN missing_dates;
