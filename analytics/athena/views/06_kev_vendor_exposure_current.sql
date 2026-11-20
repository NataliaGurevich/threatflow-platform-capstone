-- Current KEV exposure by CISA vendor/project and product for drill-down charts.
CREATE OR REPLACE VIEW threatflow_gold.kev_vendor_exposure_current AS
SELECT
    snapshot_date,
    vendor_project,
    product,
    count(*) AS vulnerability_count,
    count_if(priority_tier = 'P1') AS p1_count,
    count_if(known_ransomware_campaign_use = 'Known') AS ransomware_count,
    count_if(cisa_due_date IS NOT NULL AND cisa_due_date < snapshot_date)
        AS overdue_kev_count,
    count_if(cvss_severity = 'CRITICAL') AS critical_count,
    avg(epss_score) AS average_epss,
    max(epss_score) AS maximum_epss,
    max(cvss_score) AS maximum_cvss
FROM threatflow_gold.current_vulnerability_priority
WHERE is_kev
GROUP BY snapshot_date, vendor_project, product;
