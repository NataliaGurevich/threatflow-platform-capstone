-- Ransomware-related CISA KEV
--
-- This read-only query returns CISA KEV records whose official
-- known_ransomware_campaign_use value is Known. The flag means that ransomware
-- campaign use is known; it does not describe an organisation's exposure.

SELECT
    'P1' AS priority_tier,
    CASE
        WHEN epss.epss_score >= 0.5
            THEN 'Known exploitation, ransomware use, and EPSS >= 0.50'
        ELSE 'Known exploitation and ransomware use'
    END AS priority_reason,
    kev.cve_id,
    kev.vendor_project,
    kev.product,
    kev.vulnerability_name,
    kev.date_added AS kev_date_added,
    kev.due_date AS cisa_due_date,
    kev.required_action,
    kev.known_ransomware_campaign_use,
    round(epss.epss_score::numeric, 4) AS epss_score,
    round(epss.percentile::numeric, 4) AS epss_percentile,
    epss.score_date AS epss_score_date,
    nvd.cvss_score,
    coalesce(nullif(upper(nvd.cvss_severity), ''), 'UNKNOWN') AS cvss_severity,
    nvd.published AS nvd_published
FROM cisa_kev_vulnerabilities AS kev
LEFT JOIN epss_current AS epss USING (cve_id)
LEFT JOIN nvd_cves AS nvd USING (cve_id)
WHERE kev.known_ransomware_campaign_use = 'Known'
ORDER BY
    epss.epss_score DESC NULLS LAST,
    nvd.cvss_score DESC NULLS LAST,
    kev.date_added DESC,
    kev.cve_id;
