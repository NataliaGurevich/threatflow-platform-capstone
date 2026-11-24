# ThreatFlow data-quality gates

ThreatFlow applies fail-closed checks at every data layer. A failed gate raises an error, prevents
the layer's commit marker from being published, and therefore prevents downstream promotion.

| Layer | Checks | Failure result | Durable evidence |
| --- | --- | --- | --- |
| Bronze | Source schema, required fields, identifiers, declared counts, NVD pagination, CISA minimum/shrinkage, EPSS source date/year floor/adjacent-day ratio | Airflow task fails; accepted Bronze key is not published | Exact rejected bytes under `bronze/_quarantine/source=<source>/...` |
| Silver | Exact Bronze version/checksum/metadata, stable schema, unique business key, ranges, record counts, immutable Parquet plus manifest readback | Lambda invocation fails and SQS retries; exhausted messages reach the source DLQ | Structured `processing_failed` event, Lambda log, queue/DLQ message, unchanged prior Silver commit |
| Gold | Input manifest identity/freshness, schema, business-key uniqueness, allowed priority tiers, probability ranges, detail/summary reconciliation, Parquet readback | Glue job fails before the shared product commit and Catalog partition registration | Glue logs and terminal-state CloudWatch alarm; unchanged prior Gold commit |

## Source-specific Bronze gates

- NVD publishes a window manifest only after every page has valid pagination metadata and the
  complete `totalResults` traversal is consistent. Duplicate CVEs retain the newest
  `lastModified`; conflicting equal-version rows fail.
- CISA rejects an empty catalog, invalid records, declared-count mismatch, and a current catalog
  below 80% of the last committed Silver count. The date range in backfill does not manufacture
  historical snapshots.
- EPSS rejects missing or mismatched source dates, malformed/duplicate rows, out-of-range scores,
  date-era completeness floors, and a day below 80% of the previous committed Silver count.

The conservative count comparisons are intentional. A legitimate EPSS upstream contraction
requires investigation and an exact-date minimum in `THREATFLOW_EPSS_MINIMUM_COUNT_OVERRIDES` and
the matching Terraform variable. The default is empty; a broad or automatic bypass is not
supported.

## Idempotency and recovery

- Bronze and quarantine objects are content-addressed and written with conditional S3 requests.
- Silver objects and manifests are immutable; identical retries reuse them, while conflicting
  content fails.
- Gold uses a canonical input fingerprint and writes the shared product commit last.
- The NVD successful-coverage timestamp is advanced conditionally in S3 only after a complete
  ingestion chunk.
- Long backfills use deterministic Airflow DAG-run IDs. The Airflow API, rather than a second
  local checkpoint file, determines whether a window is missing, active, failed, or complete.

CloudWatch pipeline alarms cover Silver processing failures, stalled source queues, non-empty
DLQs, and terminal Gold Glue failures. Airflow remains the operational surface for Bronze fetch
and validation failures; the quarantine URI is logged with the failed task.
