WITH latest_snapshot AS (
    SELECT max(snapshot_date) AS snapshot_date
    FROM threatflow_gold.vulnerability_priority_summary_daily
),
selected_cve AS (
    SELECT
        detail.snapshot_date,
        detail.cve_id,
        detail.priority_tier,
        detail.epss_score
    FROM threatflow_gold.vulnerability_priority_daily AS detail
    CROSS JOIN latest_snapshot
    WHERE upper(detail.cve_id) = upper(trim({{cve_id}}))
        AND detail.snapshot_date BETWEEN
            date_add('day', -89, latest_snapshot.snapshot_date)
            AND latest_snapshot.snapshot_date
),
peer_group AS (
    SELECT
        selected.snapshot_date,
        selected.priority_tier,
        count(peer.cve_id) AS peer_count,
        avg(peer.epss_score) AS peer_average_epss,
        approx_percentile(peer.epss_score, 0.5) AS peer_median_epss,
        approx_percentile(peer.epss_score, 0.9) AS peer_p90_epss
    FROM selected_cve AS selected
    JOIN threatflow_gold.vulnerability_priority_daily AS peer
        ON peer.snapshot_date = selected.snapshot_date
        AND peer.priority_tier = selected.priority_tier
        AND upper(peer.cve_id) <> upper(selected.cve_id)
    WHERE peer.epss_score IS NOT NULL
    GROUP BY selected.snapshot_date, selected.priority_tier
)
SELECT
    selected.snapshot_date,
    selected.priority_tier,
    peer.peer_count,
    round(selected.epss_score * 100, 2) AS selected_cve_epss_percent,
    round(peer.peer_average_epss * 100, 2) AS peer_average_epss_percent,
    round(peer.peer_median_epss * 100, 2) AS peer_median_epss_percent,
    round(peer.peer_p90_epss * 100, 2) AS peer_p90_epss_percent
FROM selected_cve AS selected
LEFT JOIN peer_group AS peer
    ON peer.snapshot_date = selected.snapshot_date
    AND peer.priority_tier = selected.priority_tier
ORDER BY selected.snapshot_date;
