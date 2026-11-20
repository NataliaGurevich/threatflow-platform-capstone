# Athena Gold validation

Run `analytics/athena/gold_vulnerability_priority_validation.sql` in Amazon Athena with:

- data source: `AwsDataCatalog`;
- database: `threatflow_gold`;
- engine: Athena engine version 3;
- workgroup query-result location configured in S3.

The query is read-only. It validates all registered `snapshot_date` partitions of
`vulnerability_priority_daily` and `vulnerability_priority_summary_daily` and returns one row.
Do not create the Metabase serving views until `overall_status` is `PASS`.

Expected invariants:

- detail and summary cover the same number of snapshot dates;
- `(snapshot_date, cve_id)` is unique in detail;
- `(snapshot_date, priority_tier)` is unique in summary;
- priority tiers are only `P1`, `P2`, `P3`, and `WATCH`;
- EPSS probabilities and percentiles are in the inclusive range `[0, 1]`;
- summary contains exactly four tier rows for every date;
- summary counts, average EPSS, and maximum EPSS reconcile with detail.

The query scans the complete registered Gold history. Use it as a deployment or periodic quality
check, not as a frequently refreshed Metabase card. Dashboard queries added in the next step will
use partition filters and the summary table where possible.
