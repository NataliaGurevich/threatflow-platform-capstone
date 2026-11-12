# S3 Bronze verification — 2026-11-12

## Result

The local-to-S3 Bronze path is operational for NVD, CISA KEV and EPSS. Daily Airflow runs
completed successfully with both local and S3 locations recorded for their latest accepted
artifacts. Historical reconciliation has no missing eligible S3 locations, and an exact-byte
restore from S3 was completed without changing the manifest.

One pre-fix CISA `git_history_invalid` artifact has a legacy S3 location. The reconciliation
query now excludes this request mode, so it cannot recur. The existing object/location must be
removed through the documented, versioning-aware one-time cleanup before Bronze is marked fully
complete.

## Reconciliation evidence

Accepted artifacts with verified S3 locations:

| Source | Objects | Bytes |
| --- | ---: | ---: |
| CISA KEV | 339 | 479,461,018 |
| EPSS | 2,028 | 2,777,720,213 |
| NVD | 1,329 | 973,341,309 |
| **Total** | **3,696** | **4,230,522,540** |

For each source, the count of eligible local artifacts without an S3 location was zero. The
eligibility rule for CISA is an allowlist of `snapshot` and `git_history`; diagnostic
`git_history_invalid` artifacts are not accepted Bronze candidates.

## Daily Airflow evidence

Successful manual runs on 2026-11-12 UTC:

| DAG | Run ID | Result |
| --- | --- | --- |
| `nvd_daily` | `manual__2026-11-12T06:56:58.799850+00:00` | success |
| `cisa_daily` | `manual__2026-11-12T07:05:04.715542+00:00` | success |
| `epss_daily` | `manual__2026-11-12T07:05:10.162790+00:00` | success |

The latest accepted manifest row associated with each run had both `local` and `s3` locations.
The running Airflow scheduler returned an empty result from `airflow dags list-import-errors`.

## Restore evidence

The non-invasive restore drill selected this 146-byte NVD artifact:

```text
3e7a7c53143c3f07c1984b763e09f93c3c72b9dfee3d9e8d14f682ac4033b1bc
```

It was read from its recorded S3 version, independently checked for size and SHA-256, and
atomically written beneath `/tmp/threatflow-bronze-restore-demo`. The command returned
`local_created=true` and `manifest_updated=false`. A separate `shasum -a 256` check matched the
manifest digest exactly.

## Safety and retention

- The drill did not fetch a public feed or write normalized application tables.
- No development Raw files were removed.
- Local Raw retention remains indefinite for the capstone; automated local cleanup is disabled.
- The bucket retains current content-addressed objects. Noncurrent versions expire after the
  Terraform-configured retention period.
- S3 storage, request, retained-version and future telemetry charges remain usage-based. Request
  metrics and CloudTrail data events should be enabled only with an explicit cost/retention
  decision; Airflow task failures currently provide application-level upload failure visibility.

## Remaining one-time cleanup

The legacy invalid object is recoverably removable by creating an S3 delete marker rather than
permanently deleting its recorded version. Only after that succeeds should its S3 location row be
removed from `raw_artifact_locations`. Versioning keeps the prior object version recoverable until
the noncurrent-version lifecycle expires. The Airflow identity must not receive `s3:DeleteObject`;
cleanup requires a separate administrative identity and explicit approval.
