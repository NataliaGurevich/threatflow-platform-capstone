-- Data Quality & Reliability: overall status KPI.
-- This is a single read-only SELECT suitable for a Metabase scalar card.
-- Cross-source coverage is intentionally excluded because source differences
-- are informational rather than automatic data-quality failures.

WITH runtime AS (
    SELECT
        CURRENT_TIMESTAMP AS checked_at,
        (CURRENT_TIMESTAMP AT TIME ZONE 'UTC')::date AS current_utc_date
),
nvd_freshness AS (
    SELECT covered_until AS freshness_anchor
    FROM ingestion_checkpoints
    WHERE source = 'nvd'
),
cisa_freshness AS (
    SELECT max(updated_at) AS freshness_anchor
    FROM cisa_kev_vulnerabilities
),
epss_freshness AS (
    SELECT max(score_date) AS latest_score_date
    FROM epss_current
),
epss_expected_dates AS (
    SELECT generated_date::date AS score_date
    FROM epss_freshness
    CROSS JOIN LATERAL generate_series(
        greatest(latest_score_date - 89, date '2021-04-14'),
        latest_score_date,
        interval '1 day'
    ) AS generated_date
),
epss_missing_dates AS (
    SELECT count(*) AS issue_count
    FROM epss_expected_dates AS expected
    LEFT JOIN epss_daily_summaries AS actual USING (score_date)
    WHERE actual.score_date IS NULL
),
epss_detail_by_date AS (
    SELECT
        score_date,
        count(*) AS record_count,
        avg(epss_score) AS average_score,
        max(epss_score) AS maximum_score,
        count(*) FILTER (WHERE epss_score < 0.1) AS low_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.1 AND epss_score < 0.5)
            AS medium_risk_count,
        count(*) FILTER (WHERE epss_score >= 0.5) AS high_risk_count,
        count(*) FILTER (
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                OR epss_score < 0 OR epss_score > 1
                OR percentile < 0 OR percentile > 1
        ) AS invalid_value_count
    FROM epss_scores
    GROUP BY score_date
),
epss_summary_issues AS (
    SELECT count(*) AS issue_count
    FROM epss_detail_by_date AS detail
    LEFT JOIN epss_daily_summaries AS summary USING (score_date)
    WHERE summary.score_date IS NULL
        OR detail.record_count IS DISTINCT FROM summary.record_count
        OR abs(detail.average_score - summary.average_score) > 0.0000000001
        OR abs(detail.maximum_score - summary.maximum_score) > 0.0000000001
        OR detail.low_risk_count IS DISTINCT FROM summary.low_risk_count
        OR detail.medium_risk_count IS DISTINCT FROM summary.medium_risk_count
        OR detail.high_risk_count IS DISTINCT FROM summary.high_risk_count
),
normalized_invalid_values AS (
    SELECT
        (
            SELECT count(*)
            FROM nvd_cves
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                OR (published IS NOT NULL AND last_modified < published)
                OR (cvss_score IS NOT NULL AND (cvss_score < 0 OR cvss_score > 10))
                OR (
                    cvss_score IS NOT NULL
                    AND (
                        cvss_version IS NULL OR btrim(cvss_version) = ''
                        OR cvss_severity IS NULL OR btrim(cvss_severity) = ''
                    )
                )
        )
        + (
            SELECT count(*)
            FROM cisa_kev_vulnerabilities
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                OR due_date < date_added
                OR btrim(vendor_project) = ''
                OR btrim(product) = ''
                OR btrim(vulnerability_name) = ''
                OR btrim(short_description) = ''
                OR btrim(required_action) = ''
                OR known_ransomware_campaign_use NOT IN ('Known', 'Unknown')
        )
        + (
            SELECT count(*)
            FROM epss_current
            WHERE cve_id !~ '^CVE-[0-9]{4}-[0-9]{4,}$'
                OR epss_score < 0 OR epss_score > 1
                OR percentile < 0 OR percentile > 1
        )
        + (
            SELECT count(*)
            FROM epss_daily_summaries
            WHERE record_count <= 0
                OR average_score < 0 OR average_score > 1
                OR maximum_score < 0 OR maximum_score > 1
                OR maximum_score < average_score
                OR low_risk_count < 0
                OR medium_risk_count < 0
                OR high_risk_count < 0
                OR low_risk_count + medium_risk_count + high_risk_count <> record_count
        )
        + coalesce((SELECT sum(invalid_value_count) FROM epss_detail_by_date), 0)
            AS issue_count
),
raw_manifest_health AS (
    SELECT
        count(*) FILTER (
            WHERE sha256 !~ '^[0-9a-f]{64}$'
                OR btrim(storage_path) = ''
                OR btrim(extension) = ''
                OR size_bytes <= 0
                OR seen_count < 1
                OR last_seen_at < first_acquired_at
                OR requested_end < requested_start
                OR page_start_index < 0
                OR record_count < 0
        )
        + count(*) FILTER (WHERE source NOT IN ('nvd', 'cisa_kev', 'epss'))
        + 3 - count(DISTINCT source) FILTER (WHERE source IN ('nvd', 'cisa_kev', 'epss'))
            AS issue_count
    FROM raw_artifacts
),
latest_epss_volume AS (
    SELECT score_date, record_count
    FROM epss_daily_summaries
    ORDER BY score_date DESC
    LIMIT 1
),
latest_epss_volume_signal AS (
    SELECT
        latest.score_date,
        latest.record_count,
        baseline.previous_7d_average,
        100.0 * (latest.record_count - baseline.previous_7d_average)
            / nullif(baseline.previous_7d_average, 0) AS deviation_percentage
    FROM latest_epss_volume AS latest
    CROSS JOIN LATERAL (
        SELECT avg(record_count) AS previous_7d_average
        FROM (
            SELECT record_count
            FROM epss_daily_summaries
            WHERE score_date < latest.score_date
            ORDER BY score_date DESC
            LIMIT 7
        ) AS previous_days
    ) AS baseline
),
signals AS (
    SELECT
        'NVD freshness' AS signal,
        CASE
            WHEN freshness_anchor IS NULL THEN 'CRITICAL'
            WHEN freshness_anchor > runtime.checked_at + interval '5 minutes' THEN 'CRITICAL'
            WHEN runtime.checked_at - freshness_anchor <= interval '36 hours' THEN 'OK'
            WHEN runtime.checked_at - freshness_anchor <= interval '72 hours' THEN 'WARNING'
            ELSE 'CRITICAL'
        END AS status
    FROM nvd_freshness
    CROSS JOIN runtime

    UNION ALL

    SELECT
        'CISA KEV freshness',
        CASE
            WHEN freshness_anchor IS NULL THEN 'CRITICAL'
            WHEN freshness_anchor > runtime.checked_at + interval '5 minutes' THEN 'CRITICAL'
            WHEN runtime.checked_at - freshness_anchor <= interval '36 hours' THEN 'OK'
            WHEN runtime.checked_at - freshness_anchor <= interval '72 hours' THEN 'WARNING'
            ELSE 'CRITICAL'
        END
    FROM cisa_freshness
    CROSS JOIN runtime

    UNION ALL

    SELECT
        'EPSS freshness',
        CASE
            WHEN latest_score_date IS NULL THEN 'CRITICAL'
            WHEN latest_score_date > runtime.current_utc_date THEN 'CRITICAL'
            WHEN runtime.current_utc_date - latest_score_date <= 2 THEN 'OK'
            WHEN runtime.current_utc_date - latest_score_date = 3 THEN 'WARNING'
            ELSE 'CRITICAL'
        END
    FROM epss_freshness
    CROSS JOIN runtime

    UNION ALL

    SELECT 'EPSS missing dates',
        CASE WHEN issue_count = 0 THEN 'OK' ELSE 'CRITICAL' END
    FROM epss_missing_dates

    UNION ALL

    SELECT 'EPSS summary consistency',
        CASE
            WHEN NOT EXISTS (SELECT 1 FROM epss_detail_by_date) THEN 'CRITICAL'
            WHEN issue_count = 0 THEN 'OK'
            ELSE 'CRITICAL'
        END
    FROM epss_summary_issues

    UNION ALL

    SELECT 'Normalized invalid values',
        CASE WHEN issue_count = 0 THEN 'OK' ELSE 'CRITICAL' END
    FROM normalized_invalid_values

    UNION ALL

    SELECT 'Raw artifact manifest',
        CASE WHEN issue_count = 0 THEN 'OK' ELSE 'CRITICAL' END
    FROM raw_manifest_health

    UNION ALL

    SELECT 'EPSS volume',
        CASE
            WHEN previous_7d_average IS NULL THEN 'WARNING'
            WHEN abs(deviation_percentage) >= 20 THEN 'CRITICAL'
            WHEN abs(deviation_percentage) >= 5 THEN 'WARNING'
            ELSE 'OK'
        END
    FROM latest_epss_volume_signal
),
signal_counts AS (
    SELECT
        count(*) AS evaluated_signal_count,
        count(*) FILTER (WHERE status = 'CRITICAL') AS critical_signal_count,
        count(*) FILTER (WHERE status = 'WARNING') AS warning_signal_count
    FROM signals
)
SELECT
    CASE
        WHEN evaluated_signal_count < 8 THEN 'CRITICAL'
        WHEN critical_signal_count > 0 THEN 'CRITICAL'
        WHEN warning_signal_count > 0 THEN 'WARNING'
        ELSE 'OK'
    END AS "Overall status",
    critical_signal_count AS "Critical signals",
    warning_signal_count AS "Warning signals",
    evaluated_signal_count AS "Signals evaluated",
    runtime.checked_at AS "Checked at"
FROM signal_counts
CROSS JOIN runtime;
