SELECT
    snapshot_date,
    priority_tier,
    vulnerability_count
FROM threatflow_gold.priority_trend_daily
WHERE snapshot_date >= date_add(
    'day',
    -89,
    (SELECT max(snapshot_date) FROM threatflow_gold.priority_trend_daily)
)
ORDER BY snapshot_date, priority_rank;
