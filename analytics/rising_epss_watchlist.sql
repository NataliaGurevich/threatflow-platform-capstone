-- Rising EPSS Watchlist
--
-- This read-only query returns the CVEs that match the WATCH rule used by the
-- Vulnerability Priority Queue. Missing seven-day history cannot create an
-- alert because the comparison uses an inner join to the exact prior date.

WITH rising_scores AS (
    SELECT
        current_score.cve_id,
        current_score.score_date AS epss_score_date,
        previous_score.score_date AS comparison_date,
        current_score.epss_score,
        current_score.percentile AS epss_percentile,
        previous_score.epss_score AS epss_7d_ago,
        previous_score.percentile AS epss_percentile_7d_ago,
        current_score.epss_score - previous_score.epss_score AS epss_7d_change,
        current_score.percentile - previous_score.percentile AS percentile_7d_change,
        nvd.cvss_score,
        coalesce(nullif(upper(nvd.cvss_severity), ''), 'UNKNOWN') AS cvss_severity,
        nvd.published AS nvd_published,
        nvd.description
    FROM epss_current AS current_score
    JOIN epss_scores AS previous_score
        ON previous_score.cve_id = current_score.cve_id
        AND previous_score.score_date = current_score.score_date - 7
    JOIN nvd_cves AS nvd
        ON nvd.cve_id = current_score.cve_id
    LEFT JOIN cisa_kev_vulnerabilities AS kev
        ON kev.cve_id = current_score.cve_id
    WHERE kev.cve_id IS NULL
        AND upper(nvd.cvss_severity) IN ('HIGH', 'CRITICAL')
        AND current_score.epss_score < 0.5
        AND current_score.epss_score - previous_score.epss_score >= 0.05
)
SELECT
    'WATCH' AS priority_tier,
    'HIGH/CRITICAL CVSS and EPSS rose >= 0.05 in 7 days; not in KEV'
        AS priority_reason,
    cve_id,
    round(epss_score::numeric, 4) AS epss_score,
    round(epss_7d_ago::numeric, 4) AS epss_7d_ago,
    round(epss_7d_change::numeric, 4) AS epss_7d_change,
    round(epss_percentile::numeric, 4) AS epss_percentile,
    round(epss_percentile_7d_ago::numeric, 4) AS epss_percentile_7d_ago,
    round(percentile_7d_change::numeric, 4) AS percentile_7d_change,
    cvss_score,
    cvss_severity,
    epss_score_date,
    comparison_date,
    nvd_published,
    description
FROM rising_scores
ORDER BY
    epss_7d_change DESC,
    epss_score DESC,
    cve_id;
