-- Data Quality & Reliability: invalid normalized value counts.
-- This is a single read-only SELECT suitable for a Metabase table card.
-- Each source table is aggregated once, including the retained EPSS detail table.

WITH nvd_quality AS (
    SELECT
        count(*) AS checked_rows,
        count(*) FILTER (
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
        ) AS invalid_cve_id,
        count(*) FILTER (
            WHERE published IS NOT NULL
                AND last_modified IS NOT NULL
                AND last_modified < published
        ) AS invalid_timestamp_order,
        count(*) FILTER (
            WHERE cvss_score IS NOT NULL
                AND (cvss_score < 0 OR cvss_score > 10)
        ) AS invalid_cvss_score,
        count(*) FILTER (
            WHERE cvss_score IS NOT NULL
                AND (
                    cvss_version IS NULL
                    OR btrim(cvss_version) = ''
                    OR cvss_severity IS NULL
                    OR btrim(cvss_severity) = ''
                )
        ) AS incomplete_cvss_metadata
    FROM nvd_cves
),
cisa_quality AS (
    SELECT
        count(*) AS checked_rows,
        count(*) FILTER (
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
        ) AS invalid_cve_id,
        count(*) FILTER (WHERE due_date < date_added) AS invalid_date_order,
        count(*) FILTER (
            WHERE btrim(vendor_project) = ''
                OR btrim(product) = ''
                OR btrim(vulnerability_name) = ''
                OR btrim(short_description) = ''
                OR btrim(required_action) = ''
        ) AS blank_required_text,
        count(*) FILTER (
            WHERE known_ransomware_campaign_use NOT IN ('Known', 'Unknown')
        ) AS invalid_ransomware_value
    FROM cisa_kev_vulnerabilities
),
epss_detail_quality AS (
    SELECT
        count(*) AS checked_rows,
        count(*) FILTER (
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
        ) AS invalid_cve_id,
        count(*) FILTER (
            WHERE epss_score < 0 OR epss_score > 1
        ) AS invalid_epss_score,
        count(*) FILTER (
            WHERE percentile < 0 OR percentile > 1
        ) AS invalid_percentile
    FROM epss_scores
),
epss_current_quality AS (
    SELECT
        count(*) AS checked_rows,
        count(*) FILTER (
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
        ) AS invalid_cve_id,
        count(*) FILTER (
            WHERE epss_score < 0 OR epss_score > 1
        ) AS invalid_epss_score,
        count(*) FILTER (
            WHERE percentile < 0 OR percentile > 1
        ) AS invalid_percentile
    FROM epss_current
),
epss_summary_quality AS (
    SELECT
        count(*) AS checked_rows,
        count(*) FILTER (WHERE record_count <= 0) AS invalid_record_count,
        count(*) FILTER (
            WHERE average_score < 0 OR average_score > 1
        ) AS invalid_average_score,
        count(*) FILTER (
            WHERE maximum_score < 0
                OR maximum_score > 1
                OR maximum_score < average_score
        ) AS invalid_maximum_score,
        count(*) FILTER (
            WHERE low_risk_count < 0
                OR medium_risk_count < 0
                OR high_risk_count < 0
                OR low_risk_count + medium_risk_count + high_risk_count <> record_count
        ) AS invalid_risk_band_counts
    FROM epss_daily_summaries
),
checks AS (
    SELECT 'NVD' AS data_scope, 'Invalid CVE ID' AS check_name,
        invalid_cve_id AS invalid_count, checked_rows FROM nvd_quality
    UNION ALL
    SELECT 'NVD', 'last_modified before published',
        invalid_timestamp_order, checked_rows FROM nvd_quality
    UNION ALL
    SELECT 'NVD', 'CVSS score outside 0..10',
        invalid_cvss_score, checked_rows FROM nvd_quality
    UNION ALL
    SELECT 'NVD', 'CVSS score missing version or severity',
        incomplete_cvss_metadata, checked_rows FROM nvd_quality
    UNION ALL
    SELECT 'CISA KEV', 'Invalid CVE ID',
        invalid_cve_id, checked_rows FROM cisa_quality
    UNION ALL
    SELECT 'CISA KEV', 'due_date before date_added',
        invalid_date_order, checked_rows FROM cisa_quality
    UNION ALL
    SELECT 'CISA KEV', 'Blank required text',
        blank_required_text, checked_rows FROM cisa_quality
    UNION ALL
    SELECT 'CISA KEV', 'Invalid ransomware value',
        invalid_ransomware_value, checked_rows FROM cisa_quality
    UNION ALL
    SELECT 'EPSS detail', 'Invalid CVE ID',
        invalid_cve_id, checked_rows FROM epss_detail_quality
    UNION ALL
    SELECT 'EPSS detail', 'EPSS score outside 0..1',
        invalid_epss_score, checked_rows FROM epss_detail_quality
    UNION ALL
    SELECT 'EPSS detail', 'Percentile outside 0..1',
        invalid_percentile, checked_rows FROM epss_detail_quality
    UNION ALL
    SELECT 'EPSS current', 'Invalid CVE ID',
        invalid_cve_id, checked_rows FROM epss_current_quality
    UNION ALL
    SELECT 'EPSS current', 'EPSS score outside 0..1',
        invalid_epss_score, checked_rows FROM epss_current_quality
    UNION ALL
    SELECT 'EPSS current', 'Percentile outside 0..1',
        invalid_percentile, checked_rows FROM epss_current_quality
    UNION ALL
    SELECT 'EPSS summaries', 'Non-positive record count',
        invalid_record_count, checked_rows FROM epss_summary_quality
    UNION ALL
    SELECT 'EPSS summaries', 'Average score outside 0..1',
        invalid_average_score, checked_rows FROM epss_summary_quality
    UNION ALL
    SELECT 'EPSS summaries', 'Invalid maximum score',
        invalid_maximum_score, checked_rows FROM epss_summary_quality
    UNION ALL
    SELECT 'EPSS summaries', 'Risk bands do not sum to record count',
        invalid_risk_band_counts, checked_rows FROM epss_summary_quality
)
SELECT
    CASE WHEN invalid_count = 0 THEN 'OK' ELSE 'CRITICAL' END AS "Status",
    data_scope AS "Data scope",
    check_name AS "Check",
    invalid_count AS "Invalid values",
    checked_rows AS "Checked rows",
    round(100.0 * invalid_count / nullif(checked_rows, 0), 6) AS "Invalid percentage"
FROM checks
ORDER BY invalid_count DESC, data_scope, check_name;
