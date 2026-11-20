SELECT
    priority_tier,
    cve_id,
    priority_reason,
    vendor_project,
    product,
    is_kev,
    known_ransomware_campaign_use,
    cisa_due_date,
    cvss_score,
    cvss_severity,
    round(epss_score, 4) AS epss_score,
    round(epss_percentile, 4) AS epss_percentile,
    round(epss_7d_change, 4) AS epss_7d_change,
    nvd_last_modified
FROM threatflow_gold.current_vulnerability_priority
WHERE 1 = 1
    [[AND upper(cve_id) LIKE concat('%', upper(trim({{cve_id}})), '%')]]
ORDER BY
    priority_rank,
    known_ransomware_campaign_use = 'Known' DESC,
    epss_score DESC NULLS LAST,
    epss_7d_change DESC NULLS LAST,
    cve_id
LIMIT 500;
