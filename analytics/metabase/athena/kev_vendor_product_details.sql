SELECT
    snapshot_date,
    priority_tier,
    cve_id,
    vulnerability_name,
    priority_reason,
    vendor_project,
    product,
    known_ransomware_campaign_use,
    kev_date_added,
    cisa_due_date,
    cvss_score,
    cvss_severity,
    round(epss_score, 4) AS epss_score,
    round(epss_percentile, 4) AS epss_percentile,
    round(epss_7d_change, 4) AS epss_7d_change,
    nvd_published,
    nvd_last_modified
FROM threatflow_gold.current_vulnerability_priority
WHERE is_kev
    AND vendor_project = {{vendor_project}}
    AND product = {{product}}
ORDER BY
    priority_rank,
    known_ransomware_campaign_use = 'Known' DESC,
    epss_score DESC NULLS LAST,
    epss_7d_change DESC NULLS LAST,
    cve_id
LIMIT 1000;
