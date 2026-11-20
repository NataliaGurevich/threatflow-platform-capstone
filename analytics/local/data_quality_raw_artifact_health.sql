-- Data Quality & Reliability: raw artifact manifest health.
-- This is a single read-only SELECT suitable for a Metabase table card.
-- It validates manifest metadata only. PostgreSQL cannot verify that a file still
-- exists on disk or that its bytes still match the stored SHA-256 digest.

WITH expected_sources AS (
    SELECT *
    FROM (
        VALUES
            ('nvd', 'NVD', 1),
            ('cisa_kev', 'CISA KEV', 2),
            ('epss', 'EPSS', 3)
    ) AS sources(source_key, source_label, source_order)
),
inventory AS (
    SELECT
        source AS source_key,
        count(*) AS artifact_count,
        sum(seen_count) AS observation_count,
        sum(size_bytes) AS stored_bytes,
        max(last_seen_at) AS latest_observation_at,
        count(*) FILTER (WHERE request_mode = 'git_history_invalid')
            AS retained_invalid_response_count,
        count(*) FILTER (WHERE record_count = 0) AS zero_record_artifact_count,
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
        ) AS manifest_issue_count
    FROM raw_artifacts
    GROUP BY source
),
source_health AS (
    SELECT
        coalesce(expected.source_key, inventory.source_key) AS source_key,
        coalesce(expected.source_label, 'Unexpected: ' || inventory.source_key) AS source_label,
        coalesce(expected.source_order, 99) AS source_order,
        inventory.artifact_count,
        inventory.observation_count,
        inventory.stored_bytes,
        inventory.latest_observation_at,
        inventory.retained_invalid_response_count,
        inventory.zero_record_artifact_count,
        coalesce(inventory.manifest_issue_count, 0)
            + CASE WHEN expected.source_key IS NULL THEN 1 ELSE 0 END AS manifest_issue_count
    FROM expected_sources AS expected
    FULL OUTER JOIN inventory USING (source_key)
)
SELECT
    CASE
        WHEN artifact_count IS NULL OR artifact_count = 0 THEN 'CRITICAL'
        WHEN manifest_issue_count > 0 THEN 'CRITICAL'
        ELSE 'OK'
    END AS "Status",
    source_label AS "Source",
    coalesce(artifact_count, 0) AS "Artifacts",
    coalesce(observation_count, 0) AS "Observations",
    coalesce(stored_bytes, 0) AS "Stored bytes",
    latest_observation_at AS "Latest observation",
    CURRENT_TIMESTAMP - latest_observation_at AS "Observation age",
    coalesce(retained_invalid_response_count, 0) AS "Retained invalid responses",
    coalesce(zero_record_artifact_count, 0) AS "Zero-record artifacts",
    manifest_issue_count AS "Manifest issues"
FROM source_health
ORDER BY
    CASE
        WHEN artifact_count IS NULL OR artifact_count = 0 OR manifest_issue_count > 0 THEN 1
        ELSE 2
    END,
    source_order,
    source_label;
