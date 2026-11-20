WITH latest_snapshot AS (
    SELECT max(snapshot_date) AS snapshot_date
    FROM threatflow_gold.vulnerability_priority_summary_daily
)
SELECT
    detail.snapshot_date,
    round(detail.epss_7d_change * 100, 2) AS epss_7d_change_percentage_points
FROM threatflow_gold.vulnerability_priority_daily AS detail
CROSS JOIN latest_snapshot
WHERE upper(detail.cve_id) = upper(trim({{cve_id}}))
    AND detail.snapshot_date BETWEEN
        date_add('day', -89, latest_snapshot.snapshot_date)
        AND latest_snapshot.snapshot_date
ORDER BY detail.snapshot_date;
