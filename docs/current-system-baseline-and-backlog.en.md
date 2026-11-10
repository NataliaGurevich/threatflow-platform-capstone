# Current-system baseline and stages 1–2 backlog

Measured on 2026-11-09 in the local Docker Compose development stack. This is not
a production capacity forecast.

## 1. Baseline

| Dataset/table | Measured state | Size |
| --- | ---: | ---: |
| `nvd_cves` | 420,597 rows | 516,415,488 B |
| `cisa_kev_vulnerabilities` | 1,769 rows | 40,681,472 B |
| `cisa_kev_changes` | ~2,007 rows | 5,070,848 B |
| `epss_scores` | 11,836,949 rows across 30 dates | 2,183,888,896 B |
| `epss_current` | ~402,048 rows | 108,421,120 B |
| `raw_artifacts` | 3,683 rows; 4,151,730,269 declared bytes | 2,334,720 B manifest |
| Raw filesystem | 4,052 files | 5,295,296 KiB (~5.05 GiB) |

EPSS covers 2026-10-10 through 2026-11-08. NVD contains 420,597 current CVEs and
CISA contains 1,769 current KEV rows.

Airflow metadata contains 9/7 successful/failed NVD runs, 1,564/219 CISA runs,
and 13/3 EPSS runs. Average completed durations are 414, 3, and 556 seconds;
maxima are 4,038, 639, and 6,176 seconds. These development totals mix scheduled,
manual, retry, and test runs and are not a production success rate.

Key findings: EPSS history dominates PostgreSQL; Raw exceeds 5 GiB on one host;
EPSS/NVD duration variance requires stage-level metrics; Raw-to-manifest
reconciliation, Metabase query measurements, and timed restore drills remain open.

## 2. Stage 0 completion

Completed: database counts/sizes/date coverage, Raw size/count/manifest totals,
and basic Airflow duration/run counts.

Still required: a reproducible read-only baseline report; Raw path/hash
reconciliation; p50/p95 stage timing over at least seven scheduled runs;
fetched/validated/written/unchanged/rejected metrics; Metabase query latency and
frequency; timed database/Raw restore; confirmed RPO/RTO, Region, budget, and
retention.

## 3. Stage 1 backlog: storage abstraction

| ID | Priority | Deliverable and acceptance criteria |
| --- | --- | --- |
| B1-01 | P0 | Backend-neutral `RawArtifactStore`; exact bytes/hash; idempotent content-addressed writes; no AWS SDK in contract |
| B1-02 | P0 | Local adapter preserves layout, atomic behavior, permissions, and existing tests |
| B1-03 | P0 | EPSS uses the contract; Raw precedes parse/DB; invalid/retry/integration paths pass |
| B1-04 | P0 | CISA daily, additive watcher, and Git backfill share the contract; watcher stores exact bytes in local content-addressed Raw, emits a synchronous pointer-only event, avoids a second download, and never replaces daily recovery |

The local scheduler is the separate `cisa_watcher_hourly` DAG at `0 * * * *`.
`cisa_daily` remains unchanged as daily recovery, and both use the one-slot
`cisa_api_pool`.
| B1-05 | P0 | NVD pages use the contract; partial pagination never advances coverage; metadata retains page/window identity |
| B1-06 | P1 | Versioned `RawArtifactCreated` pointer-only JSON envelope with serialization tests |
| B1-07 | P0 | Permission, interrupted write, duplicate, checksum, DB-after-Raw failure, and retry tests |

**Exit:** all sources work through the local adapter, source logic is independent
of physical storage, and focused unit/integration regression passes.

## 4. Stage 2 backlog: AWS foundation and S3 Bronze

| ID | Priority | Deliverable and acceptance criteria |
| --- | --- | --- |
| B2-01 | P0 | One IaC tool; reproducible tagged dev environment; reviewed plan/diff |
| B2-02 | P0 | Bronze/quarantine/Silver/Gold/results layout; public access blocked; encryption and Bronze versioning; lifecycle documented |
| B2-03 | P0 | Least-privilege acquisition/transform/Athena roles; resource and source conditions; negative access tests |
| B2-04 | P0 | S3 adapter returns bucket/key/version/hash; retry-safe; errors propagate; mocked tests need no production credentials |
| B2-05 | P0 | Versioned manifest migration supports local and S3 identities with documented rollback |
| B2-06 | P0 | Config-selected backend; local default until cutover; EPSS→CISA→NVD rollout with reconciliation and rollback |
| B2-07 | P1 | Audit/access logs, metrics, budgets, alerts, and AccessDenied/KMS runbook |
| B2-08 | P0 | Manifest-to-S3 reconciliation and versioning/replay recovery drill with measured RTO |

**Exit:** all sources persist immutable Raw to S3, manifests/checksums reconcile,
local rollback is tested, and normalized/current results remain unchanged.

