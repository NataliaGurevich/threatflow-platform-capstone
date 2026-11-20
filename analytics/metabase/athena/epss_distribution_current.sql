SELECT
    epss_band,
    vulnerability_count,
    kev_count,
    ransomware_count
FROM threatflow_gold.epss_risk_distribution_daily
WHERE snapshot_date = (
    SELECT max(snapshot_date)
    FROM threatflow_gold.epss_risk_distribution_daily
)
ORDER BY epss_band_order;
