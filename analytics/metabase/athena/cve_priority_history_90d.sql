WITH latest_snapshot AS (
    SELECT max(snapshot_date) AS snapshot_date
    FROM threatflow_gold.vulnerability_priority_summary_daily
)
SELECT
    detail.snapshot_date,
    detail.priority_tier,
    CASE detail.priority_tier
        WHEN 'P1' THEN 4
        WHEN 'P2' THEN 3
        WHEN 'P3' THEN 2
        WHEN 'WATCH' THEN 1
    END AS priority_level
FROM threatflow_gold.vulnerability_priority_daily AS detail
CROSS JOIN latest_snapshot
WHERE upper(detail.cve_id) = upper(trim({{cve_id}}))
    AND detail.snapshot_date BETWEEN
        date_add('day', -89, latest_snapshot.snapshot_date)
        AND latest_snapshot.snapshot_date
ORDER BY detail.snapshot_date;
