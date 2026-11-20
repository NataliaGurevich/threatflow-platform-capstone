SELECT
    priority_tier,
    vulnerability_count
FROM threatflow_gold.priority_trend_daily
WHERE snapshot_date = (
    SELECT max(snapshot_date)
    FROM threatflow_gold.priority_trend_daily
)
ORDER BY priority_rank;
