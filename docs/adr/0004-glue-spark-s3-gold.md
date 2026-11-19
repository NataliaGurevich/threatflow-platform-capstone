# ADR 0004: Build S3 Gold datasets with AWS Glue Spark

- Status: Accepted; local and manual AWS Glue runtime implemented, AWS deployment pending
- Date: 2026-11-19

## Context

ThreatFlow already has a local analytical MVP in PostgreSQL and Metabase. The AWS path now
publishes independently committed Parquet Silver datasets for EPSS, CISA KEV, and NVD:

```text
silver/epss_scores/score_date=YYYY-MM-DD/
silver/cisa_kev_snapshots/snapshot_kind=<kind>/snapshot_id=<id>/
silver/nvd_cve_windows/mode=<mode>/window_end=<utc>/window_id=<sha256>/
```

Each Silver partition is immutable. Its Parquet object is written first and `_manifest.json` is
written last as the commit marker. S3 notifications can be duplicated, Silver sources complete at
different times, and one NVD ingestion can publish several overlapping windows. Therefore an
individual Silver object-created event cannot define a complete cross-source Gold snapshot.

The first AWS Gold product must preserve the existing explainable `P1`, `P2`, `P3`, and `WATCH`
policy while making its exact Silver inputs, cutoff, policy version, and publication status
auditable. PostgreSQL is not an input to this AWS transformation.

## Decision

AWS Glue Spark will build Gold Parquet from committed S3 Silver inputs. AWS Glue Data Catalog will
provide explicit table schemas, and Athena will query committed Gold datasets. A crawler is not
the source of truth for schema or commit status.

The initial flow is:

```text
committed S3 Silver manifests
        -> input resolution and readiness validation
        -> AWS Glue Spark transformation
        -> S3 Gold Parquet
        -> Gold commit manifests
        -> Glue Data Catalog / Athena
        -> Metabase in a later slice
```

The first implementation is invoked manually. Scheduling or event coordination is deferred until
the single-snapshot path is verified. A later trigger must evaluate readiness for all sources; it
must not start a Gold build directly for every NVD Parquet or manifest event.

The repository now contains the locally testable Spark detail and summary transformations,
fail-closed quality gates, canonical input fingerprinting, and an immutable filesystem publisher.
The local publisher writes dataset manifests after verified Parquet and a shared product commit
last. It is the executable contract for the future S3 publisher; it does not contact AWS.

### Initial datasets and grains

The first Glue job publishes two datasets from one consistent set of inputs:

| Dataset | Grain | Partition |
| --- | --- | --- |
| `vulnerability_priority_daily` | one row per `(snapshot_date, cve_id)` | `snapshot_date` |
| `vulnerability_priority_summary_daily` | one row per `(snapshot_date, priority_tier)` | `snapshot_date` |

The summary is derived from the detail output; it does not implement the priority policy
independently. The current result is the latest committed daily snapshot, so the first slice does
not publish a separate physical `current` dataset.

Gold paths are immutable:

```text
gold/vulnerability_priority_daily/snapshot_date=YYYY-MM-DD/run_id=<input-fingerprint>/
  part-*.parquet
  _manifest.json

gold/vulnerability_priority_summary_daily/snapshot_date=YYYY-MM-DD/run_id=<input-fingerprint>/
  part-*.parquet
  _manifest.json
```

The `run_id` prevents an incomplete or conflicting attempt from overwriting another attempt. A
separate dataset-level committed-snapshot pointer or table registration will expose only the
accepted run. Its exact mechanism is deferred to the publisher slice; consumers must not infer a
commit from the presence of Parquet files alone.

### Snapshot and cutoff semantics

`snapshot_date` is the UTC Gold publication date. It is not, by itself, proof that all source
state can be reconstructed historically as of midnight on that date.

Every run has an explicit timezone-aware `source_cutoff`. Input resolution must complete before
Spark reads Parquet and must produce an immutable ordered input plan. The plan contains every
selected Silver manifest identity, schema and transform version, Parquet checksum and size, and
the source-specific watermarks described below.

An arbitrary historical backfill is unsupported until the resolver can prove complete source
coverage at the requested cutoff. It must never label today's source state with a past
`snapshot_date`.

### Committed-input rule

Glue may read a Silver Parquet object only when its sibling `_manifest.json`:

1. exists and identifies the expected dataset;
2. has a supported schema and transform version;
3. names the Parquet object expected for that dataset;
4. has a valid non-negative record count, SHA-256, and size;
5. matches the selected source partition and lineage identity.

The implementation must verify the manifest contract before starting the Glue job or in a
bounded resolver stage. Registering a broad S3 prefix in Glue Catalog does not make orphan or
uncommitted Parquet valid input.

### Source selection

#### EPSS

The detail job requires committed `epss_scores` partitions for `D` and `D - 7 days`, where `D` is
the selected EPSS score date. The Parquet `score_date`, partition date, and manifest date must
agree. The resolver records both manifest identities and rejects missing or conflicting dates.

#### CISA KEV

The job selects exactly one committed `snapshot_kind=snapshot` partition whose
`snapshot.observed_at` is not later than `source_cutoff`. It chooses the greatest
`snapshot.observed_at`, with a deterministic manifest identity as the final tie-breaker. Historical
`git_history` partitions are not candidates for the current priority snapshot.

#### NVD

NVD Silver contains complete request windows, not a current-state table. The input plan selects
the configured committed `published` baseline windows and every applicable committed `modified`
window ending no later than `source_cutoff`. Missing required windows or an unproven coverage gap
make the run `NOT_READY`.

Across selected windows Spark keeps one record per `cve_id` with the greatest source
`last_modified`. Equal `last_modified` values with different projected content are a conflict and
fail the run. Acquisition time and S3 listing order are never current-state selectors. NVD is not
partitioned by `cve_id`; time partitions and Parquet statistics remain the physical layout, with
bounded hash bucketing considered only after measurement.

The first implementation must declare the baseline coverage it requires. It must not claim
complete NVD enrichment when the available published baseline is only a documented subset.

### Priority policy

Policy version `priority-v1` preserves the existing PostgreSQL analytical semantics:

- `P1`: CISA KEV and either known ransomware use or `epss_score >= 0.50`;
- `P2`: any other CISA KEV entry;
- `P3`: non-KEV `HIGH` or `CRITICAL` CVSS and `epss_score >= 0.50`;
- `WATCH`: non-KEV `HIGH` or `CRITICAL` CVSS with a seven-day EPSS increase of at least `0.05`.

The CVE universe is the union of the selected CISA snapshot and EPSS date `D`. NVD enriches that
universe and supplies the severity required for `P3` and `WATCH`. Missing enrichment must not hide
a confirmed CISA KEV record.

The detail transformation is the only implementation of classification. Summary counts are a
grouping of the validated detail rows.

### Detail contract

`vulnerability_priority_daily` schema version 1 contains:

| Field | Type | Nullable |
| --- | --- | --- |
| `snapshot_date` | date | no |
| `source_cutoff` | timestamp UTC | no |
| `cve_id` | string | no |
| `priority_tier` | string | no |
| `priority_reason` | string | no |
| `is_kev` | boolean | no |
| `vendor_project` | string | yes |
| `product` | string | yes |
| `vulnerability_name` | string | yes |
| `known_ransomware_campaign_use` | string | yes |
| `kev_date_added` | date | yes |
| `cisa_due_date` | date | yes |
| `nvd_published` | timestamp UTC | yes |
| `nvd_last_modified` | timestamp UTC | yes |
| `cvss_version` | string | yes |
| `cvss_score` | double | yes |
| `cvss_severity` | string | no |
| `epss_score_date` | date | yes |
| `epss_score` | double | yes |
| `epss_percentile` | double | yes |
| `epss_7d_ago` | double | yes |
| `epss_7d_change` | double | yes |
| `generated_at` | timestamp UTC | no |
| `policy_version` | string | no |
| `input_fingerprint` | string | no |

`cvss_severity` uses `UNKNOWN` when NVD severity is absent or blank. Numeric presentation
rounding belongs in Athena/Metabase queries, not in stored Gold measures.

### Summary contract

`vulnerability_priority_summary_daily` schema version 1 contains:

| Field | Type | Nullable |
| --- | --- | --- |
| `snapshot_date` | date | no |
| `priority_tier` | string | no |
| `vulnerability_count` | long | no |
| `ransomware_count` | long | no |
| `overdue_kev_count` | long | no |
| `critical_count` | long | no |
| `average_epss` | double | yes |
| `maximum_epss` | double | yes |
| `generated_at` | timestamp UTC | no |
| `policy_version` | string | no |
| `input_fingerprint` | string | no |

All four tiers are emitted, including zero-count tiers, so dashboard series remain stable.

### Identity, replay, and conflict

The input fingerprint is SHA-256 over a versioned canonical document containing:

- Gold dataset and schema versions;
- policy version;
- snapshot date and source cutoff;
- ordered selected Silver manifest identities and Parquet checksums;
- source-specific watermarks and baseline declaration.

`generated_at`, S3 listing order, and Glue job identifiers are excluded. A retry with the same
fingerprint verifies and reuses the committed outputs. A different fingerprint for an already
committed snapshot date is a conflict; it is retained as an uncommitted run for diagnosis and is
not silently promoted or overwritten.

### Quality gates and commit

Before either manifest becomes committed, the job must verify:

- unique and non-null `(snapshot_date, cve_id)` detail keys;
- only `P1`, `P2`, `P3`, and `WATCH` tiers;
- EPSS scores and percentiles are null or within `[0, 1]`;
- the output snapshot date, policy version, and fingerprint are constant;
- no conflicting equal-version NVD records exist;
- source input dates and watermarks match the resolved plan;
- summary values exactly reconcile to detail;
- the sum of tier counts equals the detail row count;
- Parquet schemas and row counts match the declared Gold contracts.

Data objects are written before commit manifests. A failure before manifest publication leaves no
committed Gold dataset. Detail and summary use the same fingerprint; neither is exposed as the
accepted snapshot unless both have passed verification.

## Consequences

- The AWS Gold path remains independent of PostgreSQL.
- Glue Spark supplies a conventional scale-out path for multi-file NVD compaction and
  cross-source joins; Athena remains a query engine rather than the publication coordinator.
- The first implementation introduces Glue packaging, IAM, Catalog, job-run, log, and cost
  concerns that do not exist in the local PostgreSQL MVP.
- Silver manifest resolution is a required control-plane step. A crawler alone cannot distinguish
  committed data from orphan output.
- Direct NVD object events do not trigger repeated partial Gold builds.
- A later scheduler may use EventBridge and Step Functions, but orchestration is not part of the
  first transformation slice.
- Metabase-to-Athena configuration, query-result storage, workgroups, and cost controls remain a
  later slice after Gold is queryable and verified in Athena.

## Rejected alternatives

- A new local PostgreSQL `gold` schema: the local analytical MVP already exists, while this phase
  is specifically the S3 lakehouse evolution.
- Lambda as the Gold compute engine: the cross-source workload scans multiple NVD windows and has
  less predictable duration and memory than the bounded single-input Silver transformations.
- ECS Fargate as the initial Gold engine: it would reuse Python/PyArrow directly, but Glue Spark
  was selected to demonstrate a catalogued, distributed AWS data-engineering path.
- Triggering from every NVD Silver event: a window event does not prove that EPSS, CISA, and NVD
  coverage are jointly ready.
- Partitioning by `cve_id`: high cardinality would create excessive small partitions and files.
- Letting Athena CTAS define the first publication protocol: SQL remains useful for validation and
  consumption, but manifest verification and two-dataset atomic visibility require an explicit
  controlled publisher.
