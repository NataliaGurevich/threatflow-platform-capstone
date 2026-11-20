-- ThreatFlow overview dashboard queries.
-- Each SELECT is an independent candidate for one dashboard panel.
-- The transaction is explicitly read-only so this file cannot change application data.

BEGIN TRANSACTION READ ONLY;

-- 1. Current row counts for the three normalized sources.
SELECT source, record_count
FROM (
    SELECT 'NVD CVEs' AS source, count(*) AS record_count
    FROM nvd_cves
    UNION ALL
    SELECT 'CISA KEV', count(*)
    FROM cisa_kev_vulnerabilities
    UNION ALL
    SELECT 'EPSS current', count(*)
    FROM epss_current
) AS source_counts
ORDER BY source;

-- 2. Source freshness. source_data_date is the newest date contained in the source;
-- last_database_update is when ThreatFlow last changed a normalized row.
SELECT
    source,
    source_data_date,
    last_database_update,
    CURRENT_TIMESTAMP - last_database_update AS database_update_age
FROM (
    SELECT
        'NVD' AS source,
        max(published)::date AS source_data_date,
        max(updated_at) AS last_database_update
    FROM nvd_cves
    UNION ALL
    SELECT
        'CISA KEV',
        max(date_added),
        max(updated_at)
    FROM cisa_kev_vulnerabilities
    UNION ALL
    SELECT
        'EPSS',
        max(score_date),
        max(updated_at)
    FROM epss_current
) AS freshness
ORDER BY source;

-- 3. NVD severity distribution, including records that do not have CVSS yet.
SELECT
    coalesce(nullif(upper(cvss_severity), ''), 'UNKNOWN') AS severity,
    count(*) AS cve_count,
    round(100.0 * count(*) / sum(count(*)) OVER (), 2) AS percentage
FROM nvd_cves
GROUP BY coalesce(nullif(upper(cvss_severity), ''), 'UNKNOWN')
ORDER BY cve_count DESC;

-- 4. Number of NVD CVEs published per year.
SELECT
    extract(year FROM published)::integer AS publication_year,
    count(*) AS cve_count
FROM nvd_cves
WHERE published IS NOT NULL
GROUP BY extract(year FROM published)::integer
ORDER BY publication_year;

-- 5. Number of vulnerabilities added to CISA KEV per year.
SELECT
    extract(year FROM date_added)::integer AS added_year,
    count(*) AS kev_count
FROM cisa_kev_vulnerabilities
GROUP BY extract(year FROM date_added)::integer
ORDER BY added_year;

-- 6. CISA KEV split into the same EPSS risk bands used by ingestion summaries.
SELECT
    epss_risk_band,
    count(*) AS kev_count
FROM (
    SELECT
        CASE
            WHEN e.cve_id IS NULL THEN 'NO_EPSS'
            WHEN e.epss_score >= 0.5 THEN 'HIGH'
            WHEN e.epss_score >= 0.1 THEN 'MEDIUM'
            ELSE 'LOW'
        END AS epss_risk_band
    FROM cisa_kev_vulnerabilities AS c
    LEFT JOIN epss_current AS e USING (cve_id)
) AS classified_kev
GROUP BY epss_risk_band
ORDER BY
    CASE epss_risk_band
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END;

-- 7. Most urgent CISA KEV records by current EPSS score.
SELECT
    c.cve_id,
    c.vendor_project,
    c.product,
    c.vulnerability_name,
    c.date_added,
    c.due_date,
    round(e.epss_score::numeric, 4) AS epss_score,
    round(e.percentile::numeric, 4) AS epss_percentile,
    n.cvss_score,
    coalesce(n.cvss_severity, 'UNKNOWN') AS cvss_severity
FROM cisa_kev_vulnerabilities AS c
JOIN epss_current AS e USING (cve_id)
LEFT JOIN nvd_cves AS n USING (cve_id)
WHERE e.epss_score >= 0.5
ORDER BY e.epss_score DESC, e.percentile DESC, c.cve_id
LIMIT 25;

-- 8. CVSS coverage in NVD.
SELECT
    count(*) AS total_cves,
    count(*) FILTER (WHERE cvss_score IS NOT NULL) AS cves_with_cvss,
    count(*) FILTER (WHERE cvss_score IS NULL) AS cves_without_cvss,
    round(
        100.0 * count(*) FILTER (WHERE cvss_score IS NOT NULL) / nullif(count(*), 0),
        2
    ) AS cvss_coverage_percentage
FROM nvd_cves;

COMMIT;
