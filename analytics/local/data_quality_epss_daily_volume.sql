-- Data Quality & Reliability: EPSS daily volume and anomaly signals.
-- This is a single read-only SELECT suitable for a Metabase line chart.
-- The rolling baseline uses the previous seven rows and excludes the current day.

WITH settings AS (
    SELECT
        90 AS history_days,
        5.0::numeric AS warning_percentage,
        20.0::numeric AS critical_percentage
),
coverage AS (
    SELECT max(score_date) AS latest_score_date
    FROM epss_daily_summaries
),
recent_summaries AS (
    SELECT
        summary.score_date,
        summary.record_count
    FROM epss_daily_summaries AS summary
    CROSS JOIN coverage
    CROSS JOIN settings
    WHERE summary.score_date BETWEEN
        coverage.latest_score_date - (settings.history_days - 1)
        AND coverage.latest_score_date
),
volume_history AS (
    SELECT
        score_date,
        record_count,
        lag(record_count) OVER (ORDER BY score_date) AS previous_record_count,
        avg(record_count) OVER (
            ORDER BY score_date
            ROWS BETWEEN 7 PRECEDING AND 1 PRECEDING
        ) AS previous_7d_average
    FROM recent_summaries
),
volume_changes AS (
    SELECT
        score_date,
        record_count,
        previous_record_count,
        previous_7d_average,
        record_count - previous_record_count AS day_over_day_change,
        100.0 * (record_count - previous_record_count)
            / nullif(previous_record_count, 0) AS day_over_day_percentage,
        100.0 * (record_count - previous_7d_average)
            / nullif(previous_7d_average, 0) AS baseline_deviation_percentage
    FROM volume_history
)
SELECT
    changes.score_date AS "Score date",
    changes.record_count AS "Record count",
    round(changes.previous_7d_average, 2) AS "Previous 7d average",
    changes.day_over_day_change AS "Day-over-day change",
    round(changes.day_over_day_percentage, 4) AS "Day-over-day percentage",
    round(changes.baseline_deviation_percentage, 4) AS "7d baseline deviation percentage",
    CASE
        WHEN changes.previous_7d_average IS NULL THEN 'BASELINE'
        WHEN abs(changes.baseline_deviation_percentage) >= settings.critical_percentage
            THEN 'CRITICAL'
        WHEN abs(changes.baseline_deviation_percentage) >= settings.warning_percentage
            THEN 'WARNING'
        ELSE 'OK'
    END AS "Status"
FROM volume_changes AS changes
CROSS JOIN settings
ORDER BY changes.score_date;
