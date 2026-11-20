-- Small history source for tier trend charts: four rows per snapshot date.
CREATE OR REPLACE VIEW threatflow_gold.priority_trend_daily AS
SELECT
    snapshot_date,
    snapshot_type,
    nvd_history_complete,
    priority_tier,
    CASE priority_tier
        WHEN 'P1' THEN 1
        WHEN 'P2' THEN 2
        WHEN 'P3' THEN 3
        WHEN 'WATCH' THEN 4
    END AS priority_rank,
    vulnerability_count,
    ransomware_count,
    overdue_kev_count,
    critical_count,
    average_epss,
    maximum_epss,
    generated_at,
    policy_version,
    input_fingerprint
FROM threatflow_gold.vulnerability_priority_summary_daily;
