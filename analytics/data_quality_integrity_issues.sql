-- Data Quality & Reliability: integrity issues KPI.
-- This is a single read-only SELECT returning one numeric value for a
-- Metabase scalar card. It counts rule violations, not distinct affected rows.

WITH nvd_issues AS (
    SELECT
        count(*) FILTER (WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$')
        + count(*) FILTER (
            WHERE published IS NOT NULL
                AND last_modified IS NOT NULL
                AND last_modified < published
        )
        + count(*) FILTER (
            WHERE cvss_score IS NOT NULL AND (cvss_score < 0 OR cvss_score > 10)
        )
        + count(*) FILTER (
            WHERE cvss_score IS NOT NULL
                AND (
                    cvss_version IS NULL OR btrim(cvss_version) = ''
                    OR cvss_severity IS NULL OR btrim(cvss_severity) = ''
                )
        ) AS issue_count
    FROM nvd_cves
),
cisa_issues AS (
    SELECT
        count(*) FILTER (WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$')
        + count(*) FILTER (WHERE due_date < date_added)
        + count(*) FILTER (
            WHERE btrim(vendor_project) = ''
                OR btrim(product) = ''
                OR btrim(vulnerability_name) = ''
                OR btrim(short_description) = ''
                OR btrim(required_action) = ''
        )
        + count(*) FILTER (
            WHERE known_ransomware_campaign_use NOT IN ('Known', 'Unknown')
        ) AS issue_count
    FROM cisa_kev_vulnerabilities
),
epss_detail_by_date AS (
    SELECT
        score_date,
        count(*) AS record_count,
        avg(epss_score) AS average_score,
        max(epss_score) AS maximum_score,
        count(*) FILTER (WHERE epss_score < 0.1) AS low_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5)
            AS medium_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.5) AS high_risk_count,
        count(*) FILTER (WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$')
        + count(*) FILTER (WHERE epss_score < 0 OR epss_score > 1)
        + count(*) FILTER (WHERE percentile < 0 OR percentile > 1)
            AS invalid_value_count
    FROM epss_scores
    GROUP BY score_date
),
epss_detail_value_issues AS (
    SELECT coalesce(sum(invalid_value_count), 0) AS issue_count
    FROM epss_detail_by_date
),
epss_summary_consistency_issues AS (
    SELECT
        CASE
            WHEN NOT EXISTS (SELECT 1 FROM epss_detail_by_date) THEN 1
            ELSE count(*)
        END AS issue_count
    FROM epss_detail_by_date AS detail
    LEFT JOIN epss_daily_summaries AS summary USING (score_date)
    WHERE summary.score_date IS NULL
        OR detail.record_count IS DISTINCT FROM summary.record_count
        OR abs(detail.average_score - summary.average_score) > 0.0000000001
        OR abs(detail.maximum_score - summary.maximum_score) > 0.0000000001
        OR detail.low_risk_count IS DISTINCT FROM summary.low_risk_count
        OR detail.medium_risk_count IS DISTINCT FROM summary.medium_risk_count
        OR detail.high_risk_count IS DISTINCT FROM summary.high_risk_count
),
epss_current_issues AS (
    SELECT
        count(*) FILTER (WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$')
        + count(*) FILTER (WHERE epss_score < 0 OR epss_score > 1)
        + count(*) FILTER (WHERE percentile < 0 OR percentile > 1)
            AS issue_count
    FROM epss_current
),
epss_summary_value_issues AS (
    SELECT
        count(*) FILTER (WHERE record_count <= 0)
        + count(*) FILTER (WHERE average_score < 0 OR average_score > 1)
        + count(*) FILTER (
            WHERE maximum_score < 0
                OR maximum_score > 1
                OR maximum_score < average_score
        )
        + count(*) FILTER (
            WHERE low_risk_count < 0
                OR medium_risk_count < 0
                OR high_risk_count < 0
                OR low_risk_count + medium_risk_count + high_risk_count <> record_count
        ) AS issue_count
    FROM epss_daily_summaries
),
raw_manifest_issues AS (
    SELECT
        count(*) FILTER (
            WHERE sha256 !~ '^[0-9a-f]{64}$'
                OR btrim(storage_path) = ''
                OR btrim(extension) = ''
                OR size_bytes <= 0
                OR seen_count < 1
                OR last_seen_at < first_acquired_at
                OR requested_end < requested_start
                OR page_start_index < 0
                OR record_count < 0
        )
        + count(*) FILTER (WHERE source NOT IN ('nvd', 'cisa_kev', 'epss'))
        + 3 - count(DISTINCT source) FILTER (WHERE source IN ('nvd', 'cisa_kev', 'epss'))
            AS issue_count
    FROM raw_artifacts
),
issue_groups AS (
    SELECT issue_count FROM nvd_issues
    UNION ALL
    SELECT issue_count FROM cisa_issues
    UNION ALL
    SELECT issue_count FROM epss_detail_value_issues
    UNION ALL
    SELECT issue_count FROM epss_summary_consistency_issues
    UNION ALL
    SELECT issue_count FROM epss_current_issues
    UNION ALL
    SELECT issue_count FROM epss_summary_value_issues
    UNION ALL
    SELECT issue_count FROM raw_manifest_issues
)
SELECT sum(issue_count) AS "Integrity issues"
FROM issue_groups;
