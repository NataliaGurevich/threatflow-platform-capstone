-- Data Quality & Reliability: source freshness.
-- This is a single read-only SELECT suitable for a Metabase table card.

WITH freshness AS (
    SELECT
        'NVD' AS source,
        max(last_modified) AS latest_source_data_at,
        max(updated_at) AS latest_database_update_at,
        (
            SELECT covered_until
            FROM ingestion_checkpoints
            WHERE source = 'nvd'
        ) AS freshness_anchor_at,
        interval '36 hours' AS warning_after,
        interval '72 hours' AS critical_after
    FROM nvd_cves

    UNION ALL

    SELECT
        'CISA KEV',
        max(date_added)::timestamp AT TIME ZONE 'UTC',
        max(updated_at),
        max(updated_at),
        interval '36 hours',
        interval '72 hours'
    FROM cisa_kev_vulnerabilities
),
timestamp_status AS (
    SELECT
        source,
        latest_source_data_at,
        latest_database_update_at,
        freshness_anchor_at,
        CURRENT_TIMESTAMP - freshness_anchor_at AS freshness_age,
        CASE
            WHEN freshness_anchor_at IS NULL THEN 'CRITICAL'
            WHEN freshness_anchor_at > CURRENT_TIMESTAMP + interval '5 minutes' THEN 'CRITICAL'
            WHEN CURRENT_TIMESTAMP - freshness_anchor_at <= warning_after THEN 'OK'
            WHEN CURRENT_TIMESTAMP - freshness_anchor_at <= critical_after THEN 'WARNING'
            ELSE 'CRITICAL'
        END AS status
    FROM freshness
),
epss_status AS (
    SELECT
        'EPSS' AS source,
        max(score_date)::timestamp AT TIME ZONE 'UTC' AS latest_source_data_at,
        max(updated_at) AS latest_database_update_at,
        max(score_date)::timestamp AT TIME ZONE 'UTC' AS freshness_anchor_at,
        ((CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - max(score_date)) * interval '1 day'
            AS freshness_age,
        CASE
            WHEN max(score_date) IS NULL THEN 'CRITICAL'
            WHEN max(score_date) > (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date THEN 'CRITICAL'
            WHEN (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - max(score_date) <= 2 THEN 'OK'
            WHEN (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date - max(score_date) = 3 THEN 'WARNING'
            ELSE 'CRITICAL'
        END AS status
    FROM epss_current
)
SELECT
    source AS "Source",
    latest_source_data_at AS "Latest source data",
    latest_database_update_at AS "Latest database update",
    freshness_anchor_at AS "Freshness anchor",
    freshness_age AS "Freshness age",
    status AS "Status"
FROM (
    SELECT * FROM timestamp_status
    UNION ALL
    SELECT * FROM epss_status
) AS source_status
ORDER BY
    CASE status
        WHEN 'CRITICAL' THEN 1
        WHEN 'WARNING' THEN 2
        ELSE 3
    END,
    source;
