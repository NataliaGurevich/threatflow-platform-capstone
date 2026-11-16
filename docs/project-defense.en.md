# ThreatFlow project defense

## One-minute summary

ThreatFlow is a data-engineering capstone that turns three public but semantically different
cybersecurity sources into a reproducible investigation product. It acquires NVD vulnerability
records, the CISA Known Exploited Vulnerabilities (KEV) catalog, and FIRST EPSS daily scores;
preserves exact source bytes; validates completeness and meaning; and publishes an explainable
priority queue through PostgreSQL analytical SQL and Metabase.

The product answers:

> Which CVEs should an analyst investigate first, **if the affected products are present in the
> organisation**?

That qualification is essential. ThreatFlow has no asset inventory, installed-version evidence,
network exposure, business criticality, compensating controls, or remediation status. CVSS is
technical severity, EPSS is estimated exploitation probability, and KEV is evidence of
exploitation in the wild. None proves local exposure.

## Scope, users, and supported decisions

| Persona | Decision or question | ThreatFlow output |
| --- | --- | --- |
| Vulnerability-management analyst | Which CVEs deserve investigation first? | Explainable `P1`, `P2`, `P3`, and `WATCH` queue |
| SOC / threat-intelligence analyst | What is exploited and what signal is rising? | KEV status, ransomware context, EPSS level and trend |
| Security engineer | What is known about a CVE, product, vendor, or weakness? | Searchable NVD context and cross-source joins by CVE ID |
| Incident responder | What public evidence is available for this CVE now? | Unified current NVD, KEV, and EPSS context |
| Data/platform owner | Is the product fresh, complete, and recoverable? | Freshness, coverage, manifest, checkpoint, and quality queries |

In scope are public-data ingestion, immutable Raw evidence, source-aware validation,
incremental/replay-safe loading, orchestration, a relational serving layer, analytical SQL,
dashboards, recovery controls, tests, and documentation. Organisation-specific vulnerability
management and automated remediation are explicitly out of scope.

## Architecture choices considered

The sources are batch-oriented: NVD is a paginated mutable API, CISA publishes an irregular
complete snapshot, and EPSS publishes one complete score set per day. A high-volume streaming
platform would add machinery without changing those source semantics.

| Variant | Shape | Advantages | Disadvantages | Fit |
| --- | --- | --- | --- | --- |
| 1. Local batch MVP — selected | Airflow → Python ingestion → immutable local Raw + PostgreSQL → SQL/Metabase | Few components; reproducible on a laptop; transactional UPSERTs; fast joins; low cost; easiest to demonstrate and test | Raw is host-bound; ingestion and analytics share PostgreSQL; large multi-year replay is less efficient | Best capstone balance and the implemented core |
| 2. Intermediate S3 batch | Existing Airflow → S3 Bronze → Airflow transforms → partitioned Parquet + PostgreSQL → Athena/BI | Durable shared Raw; separates historical analytics; measures real scale before adding events | Transform remains coupled to acquisition; no queue/DLQ isolation; more cloud operations and cost | Sensible controlled migration step |
| 3. Event-driven AWS lakehouse | S3 Bronze → SQS/Lambda or managed compute → Parquet/Iceberg Silver/Gold; PostgreSQL/RDS for current state; Athena for history | Independent scaling, durable buffering, cheap replay, long history, clear DLQ and cloud monitoring paths | IAM, deployment, compaction, schemas, observability, and cost are materially more complex | Target only when volume, latency, and reliability justify it |

Variant 1 was selected because it proves the difficult engineering properties—source semantics,
idempotency, integrity, recovery, lineage, and a usable data product—without hiding them behind a
large platform. Kafka, Spark, Kubernetes, Celery/Redis, and a warehouse are not needed at current
volume. The architecture still has explicit seams (`RawArtifactStore`, repositories, application
services, analytical SQL) for evolution.

## What is implemented, deployed, and planned

| Capability | Status | Defendable statement |
| --- | --- | --- |
| Docker Compose platform: PostgreSQL 17, Airflow 3.1 LocalExecutor, Metabase | Implemented locally | Reproducible local serving and orchestration stack with separate logical databases for application, Airflow metadata, and Metabase metadata |
| NVD, CISA, EPSS ingestion and backfill | Implemented | Shared application services work from Airflow and standalone CLI paths |
| Immutable local Raw storage and PostgreSQL manifest | Implemented | Exact bytes are content-addressed by source/SHA-256 and retained for replay/audit |
| Current/history/control tables and analytical SQL | Implemented | Database keys, conditional UPSERTs, checkpoints, quality queries, and priority outputs are present |
| Local EPSS/NVD/CISA Parquet Silver transformations | Implemented and fixture-tested | Typed, immutable outputs use manifests as commit markers; publication/reconciliation commands are explicit |
| S3 Bronze replication | Deployed and verified in the development account on 2026-11-12 | All three sources had verified local and S3 locations; an exact-byte non-invasive restore was demonstrated; one legacy invalid CISA object still has a documented version-aware cleanup action |
| AWS S3/SQS/Lambda Silver paths and CloudWatch/Terraform definitions | Implemented in code and IaC; end-to-end deployment not claimed | Handlers, queues, DLQs, image Lambdas, IAM boundaries, notifications, dashboards, and tests exist; ADRs state deployment/runtime verification is pending |
| Full AWS lakehouse with Iceberg, Glue/Athena Gold, RDS/MWAA | Future/target | An evolution option, not the current capstone deployment |

This status boundary is more credible than presenting every checked-in cloud module as a running
service. The dated S3 evidence is in [bronze-verification.md](bronze-verification.md); architecture
decisions are in the [ADRs](adr/0001-s3-bronze-storage.md).

## Technology choices

| Technology | Why it belongs |
| --- | --- |
| Python 3.12, HTTPX | Typed, testable source clients, parsers, validation, throttling, and retries |
| SQLAlchemy 2 + Psycopg + Alembic | Explicit models, transaction boundaries, PostgreSQL access, and versioned schema changes |
| PostgreSQL 17 | Reliable unique constraints and conditional UPSERTs, current-state joins, retained history, control data, and small-scale analytics |
| Apache Airflow 3.1, LocalExecutor | Schedules, retries, timeouts, pools, concurrency, dependency control, and visible task state; it does not contain HTTP/SQL business logic |
| Docker Compose | Repeatable local topology and dependency startup without requiring cloud access |
| Metabase + analytical SQL | Read-only, explainable serving layer for analysts; SQL definitions remain reviewable and portable |
| SHA-256 content addressing | Immutable identity, deduplication, integrity verification, and traceability from accepted bytes |
| PyArrow/Parquet | Typed, compressed, partition-friendly Silver files for historical analytics and cloud evolution |
| Terraform | Reviewable, least-privilege AWS infrastructure definitions separated from application code |
| S3, SQS, Lambda, CloudWatch | Deployed only for verified Bronze where stated; otherwise implemented target components for durable object storage, bounded event processing, and operations |
| Pytest, Testcontainers, Ruff | Unit/orchestration regression checks, disposable PostgreSQL integration tests, and static quality checks |

## Inputs: same CVE key, different meanings

| Source | Available Raw data and grain | Change semantics | Important limitation |
| --- | --- | --- | --- |
| NVD CVE API 2.0 | Paginated JSON; one current NVD representation of a CVE, including descriptions, `published`, `lastModified`, CVSS, CWE, references, and configurations | New CVEs and later mutation; daily sync must use `lastModStartDate`/`lastModEndDate`; published and modified backfills are distinct | Nullable/delayed enrichment, rate and 120-day date-window limits, mutable pagination, and no proof of organisational exposure |
| CISA KEV | Complete JSON/CSV catalog with catalog metadata and CVE, vendor/product, date added, action, due date, and ransomware context; official Git mirror provides revisions | Irregular full-snapshot replacement, not an historical snapshot API; content hash or Git commit identifies a revision | Absence is not automatically deletion; vendor/product values are not asset identifiers; KEV does not prove the product exists locally |
| FIRST EPSS | Daily/historical compressed CSV; one CVE probability and percentile per source score date | A complete daily score set; historical key is `(cve_id, score_date)` | Publication can lag; small valid-looking files may be incomplete; model/input changes affect trends; probability is neither impact nor risk |

NVD is the hero dataset because it demonstrates mutable incremental ingestion and recovery.
CISA is the operationally useful fallback: even without enrichment it provides a confirmed-
exploitation queue. EPSS is the time-series enrichment. Joining them is justified because each
answers a different part of the same decision.

## Data flow: Raw/Bronze to Silver and analytics

```mermaid
flowchart LR
    SRC[NVD API · CISA KEV/Git · EPSS daily archives]
    AF[Airflow schedules, pools, retries, backfill]
    ING[Python clients · parsers · quality gates]
    RAW[Immutable Raw/Bronze bytes<br/>local; optional verified S3 copy]
    MAN[(Raw manifest + locations)]
    PG[(PostgreSQL<br/>current · history · controls)]
    SIL[Typed Parquet Silver<br/>local implemented; AWS path bounded separately]
    SQL[Curated analytical SQL]
    BI[Metabase / analyst]

    SRC --> AF --> ING
    ING --> RAW --> MAN
    ING --> PG --> SQL --> BI
    RAW --> SIL
```

### 1. Acquisition and immutable evidence

The ingestion service stores exact response bytes before parsing or normalized writes. Local
publication is atomic; the key is `(source, SHA-256)`, so identical retries reuse an artifact and
changed bytes create a new one. `raw_artifacts` records acquisition/request lineage and
`raw_artifact_locations` records independently verified local/S3 copies. Invalid input remains
local diagnostic evidence but is not promoted to accepted S3 Bronze.

### 2. Validation and normalization

- **NVD:** validates schema, CVE identifiers, pages, offsets, stable `totalResults`, duplicates,
  explicit UTC bounds, and source `lastModified`. A complete window is the unit of success.
- **CISA:** rejects malformed or empty catalogs, declared-count mismatches, duplicates, and
  implausible shrinkage against established state. Missing entries are not physically deleted.
- **EPSS:** validates gzip/CSV structure, source date, CVE IDs, duplicates, numeric ranges, and
  conservative date-aware completeness floors/adjacent-day comparisons with an explicit override.

Transformations select a consistent NVD projection (preferred English description, best valid
CVSS version, distinct CWE values, references), preserve CISA remediation/ransomware fields, and
preserve EPSS source date separately from acquisition time.

### 3. Idempotent persistence and integrity

- `nvd_cves` has one latest row per CVE; conditional UPSERT prevents an older `last_modified`
  response from overwriting a newer row.
- `cisa_kev_vulnerabilities` keeps latest accepted entries; `cisa_kev_changes` records baseline,
  added, modified, and removed revision events without destructive snapshot replacement.
- `epss_scores` is unique by `(cve_id, score_date)`; `epss_current` cannot regress to an older
  score date; compact daily summaries remain after detailed retention (30 inclusive days by
  default).
- Cross-source joins are logical by CVE ID, not foreign keys. Different publisher coverage is
  legitimate and missing enrichment must remain visible rather than suppressing a KEV CVE.

Transactions are bounded. Failures propagate to Airflow, normalized work rolls back, and a retry
is safe. No backfill truncates tables.

### 4. Windowing, recovery, and lineage

- NVD daily runs at `03:00 UTC`, resumes from durable `covered_until`, splits long gaps within API
  limits, and advances coverage only after a complete commit. Older gaps use explicit `modified`
  backfill; initial-publication analysis uses the separate `published` mode.
- CISA daily reconciliation runs at `04:00 UTC`; an additive hourly watcher detects changed
  content. The current feed supports one snapshot synchronization, while the official Git history
  supports historical revision processing.
- EPSS daily runs at `06:00 UTC` for the previous source date; missing dates are retried/backfilled
  by exact date.
- `threat_intel_backfill` is manual, validates source/date/mode inputs before requests, chunks
  bounded ranges, and shares source-specific one-slot pools with daily/watch tasks.

Airflow uses `catchup=False`; recovery does not rely on scheduler catchup. Raw hash, request mode,
window bounds, page index, source revision, run ID, record count, and physical location provide
lineage. For Parquet, `source_sha256` and a final manifest connect Silver output to accepted Raw.

## Resulting datasets and analyst use

The serving model contains current NVD/KEV records, recent and current EPSS, permanent EPSS daily
summaries, CISA change events, operational checkpoints, and Raw manifests. Curated SQL produces:

- an explainable priority queue: `P1` (KEV plus high EPSS or ransomware context), `P2` (other KEV),
  `P3` (high/critical CVSS plus high EPSS outside KEV), and `WATCH` (material seven-day EPSS rise);
- CVE search, ransomware subsets, rising EPSS, vendor/product/CWE analysis;
- cross-source coverage, missing-date, freshness, and Raw-integrity indicators.

Example insight: an analyst can find a critical NVD CVE newly present in KEV with a high EPSS
probability and review it before a severity-only CVE. Another CVE can enter `WATCH` because its
EPSS trend rose materially. These are investigation signals, not commands to patch blindly. The
analyst must join them with asset presence, installed version, reachability, criticality, controls,
and remediation state before making an organisation-specific decision. The project tiers are a
documented policy, not an official or universal risk score.

## Operations, governance, security, and reproducibility

### Orchestration and observability

Airflow owns scheduling, retries, timeouts, concurrency, and task state; application modules own
networking and data logic; repositories own transactions. Source-specific pools serialize daily,
watcher, and backfill work. Stage-oriented logs report validation/fetch/chunk/checkpoint/completion
and distinguish fetched from written where available. Airflow state and logs plus SQL freshness,
coverage, and integrity checks provide current observability. A shared cloud dashboard and alarms
are defined in Terraform, but should be described as deployed only after runtime evidence.

### Failure and recovery

Transient HTTP errors use bounded retries. Incomplete NVD pagination cannot advance its checkpoint;
bad CISA/EPSS payloads fail before accepted writes; committed earlier dates/chunks remain valid.
Replay uses Raw bytes and UPSERTs. Exact-byte S3 restore was demonstrated non-invasively. Database
backup scripts validate dumps, but a measured full restore/RPO/RTO drill remains follow-up work.

### Governance and security

The sources contain public vulnerability intelligence and no intended personal data. Source owner,
grain, meaning, terms, limitations, and attribution are documented. `.env` is ignored, examples
contain placeholders, and credentials are injected rather than hardcoded or logged. Application,
Airflow, Metabase metadata, and read-only analytics roles are separated. S3 definitions block
public access, enable encryption/versioning, require TLS, and scope IAM by prefix/action. Adding
asset or incident data would change sensitivity and require explicit access/retention controls.

### Testing and reproducibility

Fixture-based unit tests cover parsing, corruption, completeness, duplicates, retries, windows,
and transformations without production credentials. Airflow-independent tests validate task
adapters and backfill inputs. Testcontainers integration tests exercise PostgreSQL uniqueness,
UPSERTs, stale-update protection, rollback, replay, and migrations in disposable databases. Ruff,
Docker Compose configuration validation, Terraform validation/tests, DAG import checks, and the
safe `scripts/run-capstone-demo.sh` path provide reproducible evidence. A skipped Docker test is
`NOT VERIFIED`, never a pass.

## Limitations and realistic next steps

1. Add a small governed asset-inventory/product-matching model before claiming local exposure or
   organisation-specific prioritisation.
2. Complete and document the one-time legacy invalid CISA S3 object cleanup, preserving recoverable
   versioning semantics.
3. Perform and record full database and Raw restore drills; agree RPO/RTO and retention.
4. Improve run-level metrics for fetched, validated, written, unchanged, rejected, duration, and
   freshness; alert on actionable thresholds.
5. Deploy and verify the existing AWS Silver event paths only if their operational value justifies
   cost; then reconcile every committed Bronze item to a Silver manifest.
6. Move long EPSS/NVD history to partitioned Parquet/Athena or Iceberg only after measured volume
   and query evidence. Keep PostgreSQL for current-state serving.
7. Add CI for lint/unit/integration/IaC checks and a controlled schema-evolution policy.

The main trade-off is intentional: the current solution optimizes correctness, safe recovery,
clarity, and demonstrability before distributed scale.

## 5–10 minute defense narrative

**0:00–0:45 — problem.** ThreatFlow helps a vulnerability or SOC analyst decide what to
investigate first. State immediately that it has no asset inventory and therefore does not prove
local exposure.

**0:45–1:45 — source selection.** NVD gives severity and technical context but mutates; CISA KEV
gives confirmed exploitation as a current snapshot; EPSS gives a daily probability and trend.
Explain why no one signal is a complete risk decision.

**1:45–2:45 — architecture decision.** Show the data-flow diagram. Airflow orchestrates reusable
Python services; exact bytes go to immutable Raw; PostgreSQL provides transactional current/history
serving; SQL and Metabase expose the product. Explain that this was selected over a cloud lakehouse
to keep the capstone reproducible while preserving evolution seams.

**2:45–4:00 — difficult engineering.** Walk through one invariant per source: NVD checkpoints only
complete modified windows and rejects stale overwrite; CISA validates complete snapshots and never
blindly deletes; EPSS keys history by source date and rejects implausibly incomplete files. Replays
are safe because storage and database keys are idempotent.

**4:00–5:15 — quality and recovery.** Give the one-row EPSS example: valid CSV syntax is not enough.
Show how failures retain Raw evidence, roll back normalized writes, fail the Airflow task, and allow
exact-date/window replay. Mention pools, bounded retries, and manual backfill.

**5:15–6:30 — product.** Show the priority queue or analytical SQL. Explain one row by tracing NVD,
KEV, and EPSS contributions. Repeat that tiers are transparent project policy and require local
asset context.

**6:30–7:30 — evidence and status.** Point to fixture tests, disposable PostgreSQL integration
tests, DAG parsing, the reproducible demo, and dated S3 Bronze/restore evidence. Clearly label AWS
Silver as implemented but not claimed end-to-end deployed.

**7:30–8:00 — judgement.** Close with the next two steps: add governed asset context and prove
restore/metrics. Scale historical storage only from measured need.

## Likely curator questions

**Why three sources?**  
They are complementary: NVD describes technical severity/context, CISA confirms exploitation, and
EPSS estimates probability/trend. None alone supports the investigation decision as well.

**Why PostgreSQL rather than a warehouse?**  
At this scale PostgreSQL gives transactional conditional UPSERTs, unique constraints, fast joins,
and a locally reproducible serving layer. Columnar history is an evidence-driven next step.

**Why Airflow if each source has only one main task?**  
It provides schedules, retries, timeouts, pools, run state, logs, and a parameterized recovery path.
The source logic remains independently testable and executable, so orchestration is not lock-in.

**Is this streaming?**  
No. The publishers expose an API, snapshots, and daily files. Even the CISA watcher is polling;
events begin only after a changed internal artifact is accepted.

**How are duplicates and stale data prevented?**  
Raw uses source/SHA-256 identity; business tables have unique keys and UPSERTs; NVD compares
`lastModified`; EPSS current state compares score date; CISA changes use revision/CVE identity.

**What happens after a long outage?**  
NVD resumes from its durable successful boundary and uses `modified` backfill for older gaps. EPSS
backfills exact missing score dates. CISA keeps the last valid current state and reconciles from a
fresh snapshot or official Git revisions.

**Why no foreign keys between source CVE tables?**  
Publishers legitimately differ in scope and timing. A missing enrichment is information, not an
invalid row; logical left joins preserve confirmed KEV entries.

**How do you know a payload is complete?**  
Completeness is source-specific: stable NVD pagination totals, CISA declared counts and shrinkage
checks, and EPSS date-aware population/anomaly rules. Syntax alone is never treated as success.

**What exactly runs in AWS?**  
Dated evidence confirms development S3 Bronze replication and restore for all three sources. The
Silver handlers and Terraform topology are implemented/tested, but their end-to-end deployment is
not claimed; the full lakehouse is target architecture.

**What is the biggest product limitation?**  
No organisation asset/exposure context. The queue prioritizes public intelligence for
investigation; it cannot determine whether a particular environment is vulnerable.

## Evidence map

- [Capstone report](capstone-report.md)
- [Dataset assessment](dataset-assessment.md)
- [Data catalog](data-catalog.md)
- [Data model](data-model.md)
- [Architecture study](data-pipeline-treatflow.md)
- [Governance and responsible use](governance.md)
- [Failure and recovery demonstration](failure-recovery-demo.md)
- [S3 Bronze runtime verification](bronze-verification.md)
- [Vulnerability prioritisation policy](vulnerability-prioritization.en.md)
- [AWS infrastructure guide](../infra/README.md)

