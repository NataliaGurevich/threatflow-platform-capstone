-- Data Quality & Reliability: freshness issues KPI.
-- This is a single read-only SELECT returning one numeric value for a
-- Metabase scalar card. Both WARNING and CRITICAL sources count as issues.

WITH runtime AS (
    SELECT
        CURRENT_TIMESTAMP AS checked_at,
        (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date AS current_utc_date
),
freshness_anchors AS (
    SELECT
        (SELECT max(covered_until) FROM ingestion_checkpoints WHERE source = 'nvd')
            AS nvd_anchor,
        (SELECT max(updated_at) FROM cisa_kev_vulnerabilities) AS cisa_anchor,
        (SELECT max(score_date) FROM epss_current) AS epss_score_date
),
source_issues AS (
    SELECT
        nvd_anchor IS NULL
            OR nvd_anchor > runtime.checked_at + interval '5 minutes'
            OR runtime.checked_at - nvd_anchor > interval '36 hours' AS has_issue
    FROM freshness_anchors
    CROSS JOIN runtime

    UNION ALL

    SELECT
        cisa_anchor IS NULL
            OR cisa_anchor > runtime.checked_at + interval '5 minutes'
            OR runtime.checked_at - cisa_anchor > interval '36 hours'
    FROM freshness_anchors
    CROSS JOIN runtime

    UNION ALL

    SELECT
        epss_score_date IS NULL
            OR epss_score_date > runtime.current_utc_date
            OR runtime.current_utc_date - epss_score_date > 2
    FROM freshness_anchors
    CROSS JOIN runtime
)
SELECT count(*) FILTER (WHERE has_issue) AS "Freshness issues"
FROM source_issues;
