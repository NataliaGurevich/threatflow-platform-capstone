# Athena views for Metabase

The files in `analytics/athena/views` create a small serving layer over the committed Gold tables.
Deploy them from the repository checkout with the idempotent CLI; it validates every file, runs
the statements sequentially in numeric order, stops on the first Athena failure, and verifies each
result as a `VIRTUAL_VIEW` in Glue Catalog:

```bash
.venv/bin/python -m threatflow.gold.athena_views \
  --database threatflow_gold \
  --workgroup threatflow-metabase-dev \
  --region eu-central-1 \
  --dry-run

.venv/bin/python -m threatflow.gold.athena_views \
  --database threatflow_gold \
  --workgroup threatflow-metabase-dev \
  --region eu-central-1
```

The deployment identity uses the caller's AWS credentials; do not use the Metabase service account
for this administrative command. `CREATE OR REPLACE VIEW` is idempotent and changes Catalog
metadata only; it does not copy or rewrite Parquet data. New Gold partitions do not require a view
deployment. Re-run the command only when a view SQL definition changes or during environment
bootstrap. A CI job can invoke the same command after Terraform has created the database, tables,
workgroup, and query-results location.

| View | Grain | Intended Metabase use |
| --- | --- | --- |
| `current_vulnerability_priority` | Current date + CVE | Searchable investigation queue and drill-through |
| `vulnerability_priority_kpis_current` | One current snapshot | Overview KPI cards |
| `priority_trend_daily` | Date + priority tier | Stacked priority history chart |
| `kev_exposure_daily` | Date | KEV, ransomware, overdue remediation trends |
| `epss_risk_distribution_daily` | Date + EPSS band | EPSS distribution chart |
| `kev_vendor_exposure_current` | Current date + vendor + product | Vendor/product exposure ranking |

The `current_*` views determine the newest date from the small summary table and then select the
matching detail partition. Historical dashboard cards should filter `snapshot_date` explicitly.
The summary-backed views are preferred for overview and trend cards because they read far fewer
rows than the detail table.

After creating the views, verify them with:

```sql
SELECT * FROM threatflow_gold.vulnerability_priority_kpis_current;

SELECT snapshot_date, sum(vulnerability_count) AS vulnerabilities
FROM threatflow_gold.priority_trend_daily
GROUP BY snapshot_date
ORDER BY snapshot_date DESC
LIMIT 10;

SELECT *
FROM threatflow_gold.epss_risk_distribution_daily
WHERE snapshot_date = (SELECT max(snapshot_date) FROM threatflow_gold.priority_trend_daily)
ORDER BY epss_band_order;
```

Views are logical queries, not materialized tables. Metabase should avoid repeatedly querying
unfiltered detail history. Athena workgroup scan limits and a dedicated query-results location are
still required before connecting Metabase.
