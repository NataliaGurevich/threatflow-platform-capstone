-- Daily EPSS distribution for histogram/stacked-bar cards.
CREATE OR REPLACE VIEW threatflow_gold.epss_risk_distribution_daily AS
SELECT
    snapshot_date,
    CASE
        WHEN epss_score IS NULL THEN 'NO_EPSS'
        WHEN epss_score < 0.10 THEN '0.00-0.09'
        WHEN epss_score < 0.50 THEN '0.10-0.49'
        WHEN epss_score < 0.90 THEN '0.50-0.89'
        ELSE '0.90-1.00'
    END AS epss_band,
    CASE
        WHEN epss_score IS NULL THEN 5
        WHEN epss_score < 0.10 THEN 1
        WHEN epss_score < 0.50 THEN 2
        WHEN epss_score < 0.90 THEN 3
        ELSE 4
    END AS epss_band_order,
    count(*) AS vulnerability_count,
    count_if(is_kev) AS kev_count,
    count_if(known_ransomware_campaign_use = 'Known') AS ransomware_count,
    avg(epss_score) AS average_epss,
    max(epss_score) AS maximum_epss
FROM threatflow_gold.vulnerability_priority_daily
GROUP BY
    snapshot_date,
    CASE
        WHEN epss_score IS NULL THEN 'NO_EPSS'
        WHEN epss_score < 0.10 THEN '0.00-0.09'
        WHEN epss_score < 0.50 THEN '0.10-0.49'
        WHEN epss_score < 0.90 THEN '0.50-0.89'
        ELSE '0.90-1.00'
    END,
    CASE
        WHEN epss_score IS NULL THEN 5
        WHEN epss_score < 0.10 THEN 1
        WHEN epss_score < 0.50 THEN 2
        WHEN epss_score < 0.90 THEN 3
        ELSE 4
    END;
