SELECT
    vendor_project,
    product,
    vulnerability_count,
    p1_count,
    ransomware_count,
    overdue_kev_count,
    critical_count,
    round(average_epss, 4) AS average_epss,
    round(maximum_epss, 4) AS maximum_epss,
    maximum_cvss
FROM threatflow_gold.kev_vendor_exposure_current
ORDER BY p1_count DESC, vulnerability_count DESC, vendor_project, product
LIMIT 20;
