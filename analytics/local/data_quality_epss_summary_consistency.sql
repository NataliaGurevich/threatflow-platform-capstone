-- Data Quality & Reliability: EPSS detail-to-summary consistency.
-- This is a single read-only SELECT suitable for a Metabase table card.
-- Only retained detail dates can be recalculated; older summary-only dates
-- intentionally have no rows in epss_scores.

WITH detail_aggregates AS (
    SELECT
        score_date,
        count(*) AS record_count,
        avg(epss_score) AS average_score,
        max(epss_score) AS maximum_score,
        count(*) FILTER (WHERE epss_score < 0.1) AS low_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5)
            AS medium_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.5) AS high_risk_count
    FROM epss_scores
    GROUP BY score_date
),
comparisons AS (
    SELECT
        detail.score_date,
        detail.record_count AS detail_record_count,
        summary.record_count AS summary_record_count,
        abs(detail.average_score - summary.average_score) AS average_score_difference,
        abs(detail.maximum_score - summary.maximum_score) AS maximum_score_difference,
        detail.low_risk_count = summary.low_risk_count AS low_risk_count_matches,
        detail.medium_risk_count = summary.medium_risk_count AS medium_risk_count_matches,
        detail.high_risk_count = summary.high_risk_count AS high_risk_count_matches,
        summary.score_date IS NULL AS summary_missing
    FROM detail_aggregates AS detail
    LEFT JOIN epss_daily_summaries AS summary USING (score_date)
),
inconsistent_dates AS (
    SELECT
        *,
        concat_ws(
            ', ',
            CASE WHEN summary_missing THEN 'summary missing' END,
            CASE
                WHEN detail_record_count IS DISTINCT FROM summary_record_count
                    THEN 'record count'
            END,
            CASE
                WHEN average_score_difference IS NULL
                    OR average_score_difference > 0.0000000001
                    THEN 'average score'
            END,
            CASE
                WHEN maximum_score_difference IS NULL
                    OR maximum_score_difference > 0.0000000001
                    THEN 'maximum score'
            END,
            CASE WHEN low_risk_count_matches IS NOT TRUE THEN 'low-risk count' END,
            CASE WHEN medium_risk_count_matches IS NOT TRUE THEN 'medium-risk count' END,
            CASE WHEN high_risk_count_matches IS NOT TRUE THEN 'high-risk count' END
        ) AS failed_checks
    FROM comparisons
    WHERE
        summary_missing
        OR detail_record_count IS DISTINCT FROM summary_record_count
        OR average_score_difference IS NULL
        OR average_score_difference > 0.0000000001
        OR maximum_score_difference IS NULL
        OR maximum_score_difference > 0.0000000001
        OR low_risk_count_matches IS NOT TRUE
        OR medium_risk_count_matches IS NOT TRUE
        OR high_risk_count_matches IS NOT TRUE
),
health AS (
    SELECT
        (SELECT count(*) FROM detail_aggregates) AS checked_date_count,
        count(*) AS inconsistent_date_count
    FROM inconsistent_dates
)
SELECT
    CASE
        WHEN health.checked_date_count = 0 THEN 'CRITICAL'
        WHEN health.inconsistent_date_count = 0 THEN 'OK'
        ELSE 'CRITICAL'
    END AS "Status",
    health.checked_date_count AS "Checked dates",
    health.inconsistent_date_count AS "Inconsistent dates",
    inconsistent.score_date AS "Score date",
    inconsistent.failed_checks AS "Failed checks",
    inconsistent.detail_record_count AS "Detail rows",
    inconsistent.summary_record_count AS "Summary rows",
    inconsistent.average_score_difference AS "Average difference",
    inconsistent.maximum_score_difference AS "Maximum difference"
FROM health
LEFT JOIN inconsistent_dates AS inconsistent ON true
ORDER BY inconsistent.score_date;
