-- Daily CISA KEV/ransomware/remediation exposure aggregated across priority tiers.
CREATE OR REPLACE VIEW threatflow_gold.kev_exposure_daily AS
SELECT
    snapshot_date,
    arbitrary(snapshot_type) AS snapshot_type,
    arbitrary(nvd_history_complete) AS nvd_history_complete,
    sum(
        CASE
            WHEN priority_tier IN ('P1', 'P2') THEN vulnerability_count
            ELSE 0
        END
    ) AS kev_vulnerabilities,
    sum(ransomware_count) AS ransomware_vulnerabilities,
    sum(overdue_kev_count) AS overdue_kev_vulnerabilities,
    sum(critical_count) AS critical_vulnerabilities,
    max(maximum_epss) AS maximum_epss,
    max(generated_at) AS generated_at,
    arbitrary(policy_version) AS policy_version,
    arbitrary(input_fingerprint) AS input_fingerprint
FROM threatflow_gold.vulnerability_priority_summary_daily
GROUP BY snapshot_date;
