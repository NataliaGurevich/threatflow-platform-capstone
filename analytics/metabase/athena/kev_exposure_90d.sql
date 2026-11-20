SELECT
    snapshot_date,
    kev_vulnerabilities,
    ransomware_vulnerabilities,
    overdue_kev_vulnerabilities
FROM threatflow_gold.kev_exposure_daily
WHERE snapshot_date >= date_add(
    'day',
    -89,
    (SELECT max(snapshot_date) FROM threatflow_gold.kev_exposure_daily)
)
ORDER BY snapshot_date;
