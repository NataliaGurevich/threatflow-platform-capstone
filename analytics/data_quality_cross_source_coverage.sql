-- Data Quality & Reliability: directional cross-source CVE coverage.
-- This is a single read-only SELECT suitable for a Metabase table card.
-- Coverage differences are informational and are not automatically classified
-- as quality failures because source publication scope and timing can differ.

WITH latest_epss_date AS (
    SELECT max(score_date) AS score_date
    FROM epss_current
),
latest_epss AS (
    SELECT current_score.cve_id
    FROM epss_current AS current_score
    CROSS JOIN latest_epss_date
    WHERE current_score.score_date = latest_epss_date.score_date
),
cisa_coverage AS (
    SELECT
        count(*) AS total_count,
        count(nvd.cve_id) AS nvd_match_count,
        count(epss.cve_id) AS epss_match_count
    FROM cisa_kev_vulnerabilities AS cisa
    LEFT JOIN nvd_cves AS nvd USING (cve_id)
    LEFT JOIN latest_epss AS epss USING (cve_id)
),
nvd_coverage AS (
    SELECT
        count(*) AS total_count,
        count(epss.cve_id) AS epss_match_count
    FROM nvd_cves AS nvd
    LEFT JOIN latest_epss AS epss USING (cve_id)
),
epss_coverage AS (
    SELECT
        count(*) AS total_count,
        count(nvd.cve_id) AS nvd_match_count
    FROM latest_epss AS epss
    LEFT JOIN nvd_cves AS nvd USING (cve_id)
),
coverage_metrics AS (
    SELECT
        1 AS metric_order,
        'CISA KEV' AS source_set,
        'NVD' AS target_source,
        nvd_match_count AS matched_count,
        total_count
    FROM cisa_coverage

    UNION ALL

    SELECT
        2,
        'CISA KEV',
        'Latest EPSS',
        epss_match_count,
        total_count
    FROM cisa_coverage

    UNION ALL

    SELECT
        3,
        'NVD',
        'Latest EPSS',
        epss_match_count,
        total_count
    FROM nvd_coverage

    UNION ALL

    SELECT
        4,
        'Latest EPSS',
        'NVD',
        nvd_match_count,
        total_count
    FROM epss_coverage
)
SELECT
    source_set AS "Source set",
    target_source AS "Target source",
    matched_count AS "Matched CVEs",
    total_count - matched_count AS "Missing CVEs",
    total_count AS "Total CVEs",
    round(100.0 * matched_count / nullif(total_count, 0), 2) AS "Coverage percentage",
    latest_epss_date.score_date AS "Latest EPSS date"
FROM coverage_metrics
CROSS JOIN latest_epss_date
ORDER BY metric_order;
