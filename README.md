# ThreatFlow

ThreatFlow is a cybersecurity intelligence data engineering capstone for CISA KEV, NVD,
and EPSS. The implemented local platform provides reproducible ingestion, immutable Raw
artifacts, PostgreSQL current/history/control tables, Airflow orchestration, data-quality
checks, recovery paths, analytical SQL, and Metabase dashboards. The AWS lakehouse material
is a documented future evolution, not a claim about the current deployment.

## Capstone overview

ThreatFlow's primary user is a vulnerability-management, SOC, or threat-intelligence
analyst. Its main data product is an explainable investigation queue answering which CVEs
should be reviewed first—if the affected products are present in the organisation—using
NVD severity/context, CISA confirmed exploitation, and FIRST EPSS probability/trend.

The capstone evidence is organised here:

- [Unified capstone report](docs/capstone-report.md)
- [Candidate dataset assessment and selection](docs/dataset-assessment.md)
- [Data catalog](docs/data-catalog.md)
- [ER diagram and data model](docs/data-model.md)
- [Governance, security, privacy, and retention](docs/governance.md)
- [Failure and recovery demonstration](docs/failure-recovery-demo.md)
- [5–10 minute presentation script](docs/presentation-script.md)
- [Implemented and target architecture](docs/data-pipeline-treatflow.md)
- [S3 Bronze storage decision](docs/adr/0001-s3-bronze-storage.md)
- [Terraform AWS infrastructure](infra/README.md)
- [Vulnerability prioritisation policy](docs/vulnerability-prioritization.en.md)

Run the fixture-based local verification without external API calls or changes to the
development database:

```sh
./scripts/run-capstone-demo.sh
```

If the local Compose stack is already running and contains ingested data, add
`--with-running-stack` to execute the priority and data-quality SQL in read-only mode.

The source schema has `cisa_kev_vulnerabilities`, `nvd_cves`, and `epss_scores`. EPSS also has the derived `epss_current` and `epss_daily_summaries` tables. The separate `ingestion_checkpoints` table stores operational NVD coverage. NVD and CISA retain the latest ingested state per CVE, not a full database snapshot per run. PostgreSQL 17 runs through Docker Compose with a persistent named volume and health check.

## Raw data storage (Phase 2)

Ingestion uses the backend-neutral `RawArtifactStore` contract to preserve original response
bytes before parsing or loading. `LocalRawArtifactStore` is the currently enabled backend; the
legacy `threatflow.raw_storage.store_raw_artifact` function remains as a compatibility wrapper.
The local adapter partitions artifacts by source and acquisition month and names each file with
the SHA-256 digest of the exact bytes:

```text
data/raw/
├── cisa_kev/year=2026/month=11/<sha256>.json
├── nvd/year=2026/month=11/<sha256>.json
└── epss/year=2026/month=11/<sha256>.csv.gz
```

Artifacts are immutable: a complete temporary file is atomically published, and an existing identical artifact is reused. Changed bytes have a different digest and produce a separate file. Raw files are excluded from Git; `.gitignore` preserves the directory placeholder.

`raw_artifacts` is the searchable manifest for these files. It records source, SHA-256, physical path, size, first acquisition, last observation, observation count, request mode and interval, page offset, record count, and the Airflow run ID when available. Deduplication is global per source and hash, including across acquisition months: an identical response observed later reuses its original file and updates `last_seen_at`/`seen_count`; changed bytes create a new immutable artifact. NVD historical request dates remain queryable in the manifest while the physical path continues to represent the first acquisition month.

Set `THREATFLOW_RAW_STORAGE_BACKEND=local` and configure the storage root with
`THREATFLOW_RAW_DATA_DIR` in `.env`; it defaults to `data/raw`. Copy `.env.example` to `.env`
and change the value if you want a different local directory. Run unit tests with
`uv run python -m pytest`; storage tests use temporary directories and do not connect to
PostgreSQL. S3 is an accepted target design, not an enabled or deployed backend yet; see the
[S3 Bronze ADR](docs/adr/0001-s3-bronze-storage.md).

## Phase 1 local setup

Install uv, copy `.env.example` to `.env`, set a local PostgreSQL password, and run `uv sync --group dev`. Start the database with `docker compose up -d postgres`, then run `uv run alembic upgrade head`. Migration and PostgreSQL integration verification must use a dedicated isolated database.

## CISA KEV ingestion (Phase 3)

`threatflow.ingestion.cisa_client` downloads the complete official CISA KEV JSON with HTTPX, explicit timeouts, and bounded retries. `cisa_ingestion` timestamps acquisition, stores the exact response bytes through the Phase 2 immutable `store_raw_artifact` service, validates the catalog with Pydantic, then bulk upserts records through PostgreSQL `ON CONFLICT (cve_id) DO UPDATE`. The transaction is atomic; catalog omissions never delete database rows. Invalid catalogs or records fail ingestion with a validation error.

Configure `THREATFLOW_RAW_DATA_DIR` and PostgreSQL connection settings in `.env`. Apply the existing migration to a local database, then run `uv run python -m threatflow.ingestion.cisa_ingestion`. Unit tests use mocks and temporary storage: `uv run python -m pytest tests/unit`. Database integration verification should use a dedicated isolated PostgreSQL database, never the development database.

## NVD CVE ingestion (Phase 4)

`threatflow.ingestion.nvd_ingestion` retrieves current CVE records from the official [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities). By default it requests records modified in the preceding 48 hours using UTC `lastModStartDate` and `lastModEndDate`. The overlap recovers delayed or retried runs; repeated records are safe because PostgreSQL bulk UPSERTs by `cve_id`. `ingest_nvd_cves(start=..., end=...)` accepts an explicit timezone-aware date range. NVD date ranges are limited to 120 days.

The client retrieves all pages using `startIndex`, `resultsPerPage`, and `totalResults`, validates pagination consistency, and fails if totals change during traversal. Each exact response page is stored through existing immutable Raw Storage before parsing at `data/raw/nvd/year=YYYY/month=MM/<sha256>.json`. Invalid required records fail ingestion. Duplicate CVEs use the record with the latest `lastModified`; equal-time conflicting projected data fails. CVSS is analytically projected by preferring valid 4.0, then 3.1, 3.0, then 2.0 metrics; this is not the only valid CVSS interpretation. Missing CVSS, CWE, or references is accepted.

Set `THREATFLOW_NVD_API_KEY` optionally; credentials are sent in the `apiKey` header and are not logged. Configure the API base URL, page size, lookback, timeouts, and retries with `THREATFLOW_NVD_*` and `THREATFLOW_HTTP_*`. Requests are paced separately from retry backoff. Run locally with `uv run python -m threatflow.ingestion.nvd_ingestion`. Unit tests use mocked HTTP responses; integration tests use isolated PostgreSQL 17 Testcontainers: `uv run python -m pytest tests/unit tests/integration`.

## EPSS daily scores (Phase 5)

The official [FIRST EPSS daily file](https://www.first.org/epss/data) is downloaded as a gzip CSV with `cve`, `epss`, and `percentile` columns. The complete original `.csv.gz` bytes are stored before decompression at `data/raw/epss/year=YYYY/month=MM/<sha256>.csv.gz` (or under `THREATFLOW_RAW_DATA_DIR`). The directory uses the **acquisition** month, while each database row uses the source **score date**.

EPSS uses three database layers. `epss_current` keeps one latest row per CVE for fast joins and scoring. `epss_scores` keeps detailed daily rows for the most recent 30 inclusive score dates by default; configure this with `THREATFLOW_EPSS_HISTORY_RETENTION_DAYS`. `epss_daily_summaries` keeps one compact aggregate row per score date indefinitely. Dates older than the retained window use an aggregate-only path: the ingestion stores the immutable raw file, manifest, and daily summary directly, without first writing hundreds of thousands of immediately expired detail/current rows. Dates inside the window atomically upsert detail, current state, and summary, then prune expired detail. Reprocessing updates corrected values and summaries, and an older backfill never regresses `epss_current`. Immutable raw gzip files are not pruned and remain the recovery source.

Set PostgreSQL credentials and, if needed, `THREATFLOW_RAW_DATA_DIR`, `THREATFLOW_HTTP_CONNECT_TIMEOUT`, `THREATFLOW_HTTP_READ_TIMEOUT`, and `THREATFLOW_HTTP_RETRIES` in `.env`. Apply the existing migration to your local database before manual ingestion. Run current ingestion with:

```sh
uv run python -m threatflow.ingestion.epss_ingestion
```

Run one historical date from the [official archive](https://github.com/empiricalsec/epss_scores) with:

```sh
uv run python -m threatflow.ingestion.epss_ingestion --score-date 2024-12-21
```

Current ingestion requires the CSV's `score_date` metadata; it fails if that date cannot be established. Historical ingestion uses the dated archive filename and rejects any conflicting embedded score date. Publication may occur after the score date begins; acquisition time never supplies the score date. Invalid or incomplete files remain in immutable Raw Storage for investigation, and database changes roll back on failure. Historical files before the archive's 2021-04-14 start are unavailable. Bulk historical orchestration is outside this phase.

Run unit and isolated PostgreSQL 17 Testcontainers tests with `uv run pytest -v`. Integration tests require a working Docker daemon; skipped tests do not establish successful verification.

## Airflow orchestration

Airflow 3.1.0 uses LocalExecutor and a separate `airflow` PostgreSQL database. The application still owns HTTP requests, validation, raw artifacts, transactions, and upserts. The Airflow image installs `threatflow` in a separate Python environment because Airflow pins SQLAlchemy 1.4 while the application uses SQLAlchemy 2; ingestion tasks use `ExternalPythonOperator`. The three daily DAGs run at 03:00 NVD, 04:00 CISA, and 06:00 EPSS UTC; the additive `cisa_watcher_hourly` runs at the start of every UTC hour; `threat_intel_backfill` is manual. Each ingestion task uses a one-slot source pool shared by daily, watcher, and backfill. DAG schedules are set in the DAG files.

Copy `.env.example` to `.env`, set `THREATFLOW_POSTGRES_PASSWORD` and `AIRFLOW_ADMIN_PASSWORD`, and generate a persistent `AIRFLOW_JWT_SECRET` (for example, `openssl rand -hex 32`). Airflow components must share this secret to validate login tokens. Then start; application and Airflow metadata migrations run automatically before the long-running services:

```sh
docker compose up -d --build
```

The metadata migration and pools run in `airflow-init`. Application migrations run in `threatflow-migrate`; `airflow-init` waits for that one-shot service so DAGs cannot start against an outdated application schema. Existing PostgreSQL volumes are supported by the idempotent `airflow-db-init` database creation. Airflow UI is at http://localhost:8080. The `airflow-auth-init` service writes the configured admin password to Airflow's simple auth password file at startup. Keep `.env` outside version control. The API key remains in `THREATFLOW_NVD_API_KEY`. Standalone ingestion entry points remain available as documented above.

Unpause a daily DAG and use **Trigger DAG** for a manual run. Airflow 3.1 manual runs do not expose a data interval to task templates, so daily tasks consistently use `dag_run.run_after` as their scheduling anchor for both scheduled and manual runs. NVD daily recovers missed modification windows after its first successful checkpoint. For a gap predating that checkpoint, trigger `threat_intel_backfill` with `nvd_mode=modified`. To load CVEs originally published in an interval, use `published`; this does not reconstruct later modifications. EPSS daily requests the previous UTC score date because publication may lag. An unavailable dated archive fails the task; retry once the file is published. CISA backfill reads revisions of `known_exploited_vulnerabilities.json` from the official `cisagov/kev-data` Git mirror. It stores each validated snapshot and commit SHA in Raw Storage and `raw_artifacts` without overwriting the normalized current-state table owned by `cisa_daily`.

Example backfill trigger configuration (up to 31 inclusive days, chunks of seven by default):

```json
{"sources":["nvd","epss"],"start_date":"2025-01-01","end_date":"2025-01-07","nvd_mode":"published","chunk_days":7}
```

Use `nvd_mode=modified` to recover changes. Each source runs as one bounded task, with sequential chunks. EPSS iterates dated archive files. No API payload is passed through XCom. Backfill may also be triggered via `docker compose exec airflow-api-server airflow dags trigger threat_intel_backfill --conf '<JSON>'`.

For ranges longer than 31 days, use the resumable controller. It splits the range into sequential Airflow runs, stops on the first failure, and resumes completed windows from an atomic local checkpoint. Use a dry run first; it does not connect to Airflow:

```sh
uv run threatflow-backfill-range --sources nvd cisa epss --start 2021-04-14 --end 2026-11-03 --nvd-mode modified --dry-run
```

Then provide the Airflow password through the existing untracked `.env` and run the same command without `--dry-run`:

```sh
uv run --env-file .env threatflow-backfill-range --sources nvd epss --start 2021-04-14 --end 2026-11-03 --nvd-mode modified
```

The default outer interval is 31 inclusive days and the NVD request chunk is seven days. Configure them with `--interval-days` and `--chunk-days`. The default checkpoint is `data/backfill-checkpoint.json`, which is ignored by Git and contains no credentials. Deterministic Airflow run IDs make recovery safe if the controller exits after submission. Use a different `--checkpoint` path for a different plan. Only one process may use a checkpoint at a time. For remote Airflow, set `--airflow-url` and `--username`; pass the password through `AIRFLOW_ADMIN_PASSWORD`, not the command line or shell history.

The same controller can run without a host Python environment through the one-shot Compose CLI service. It uses the exact application runtime installed in the Airflow image, reaches Airflow over the internal Compose network, and mounts `./data` so checkpoints and raw artifacts persist on the host:

```sh
docker compose run --rm threatflow-cli backfill \
  --sources nvd epss \
  --start 2021-04-14 \
  --end 2026-11-03 \
  --nvd-mode modified \
  --checkpoint /opt/threatflow/data/full-backfill.json
```

Preview the plan safely by adding `--dry-run`. The service is in the `cli` profile and is created only for the duration of `docker compose run`; it is not a permanently running service.

Inspect the local checkpoint without contacting Airflow or PostgreSQL:

```sh
docker compose run --rm --no-deps threatflow-cli backfill-status \
  --checkpoint /opt/threatflow/data/backfill-checkpoint.json \
  --stall-after-minutes 30
```

The command reports `RUNNING`, `STALLED`, `FAILED`, `COMPLETED`, or `UNKNOWN`, plus completed and remaining windows. Exit code `0` means running or completed, `1` means failed, and `2` means stalled, unknown, or invalid input. `--no-deps` is intentional: checkpoint inspection must remain available when Airflow or PostgreSQL is unavailable. Rebuild the `threatflow-cli` image after changing application code.

CLI command references with important options, exit codes, and safety notes are
available in [Russian](docs/for_me/cli-commands.md) and
[English](docs/for_me/cli-commands.en.md).

## Dashboard query prototype

`analytics/threatflow_overview.sql` contains independent read-only queries for an initial
overview dashboard: source counts and freshness, NVD severity and publication trends,
CISA KEV additions and EPSS risk, the highest-risk KEV records, and CVSS coverage. Run
all queries against the local application database with:

```sh
docker compose exec -T postgres sh -c \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' \
  < analytics/threatflow_overview.sql
```

The SQL file starts an explicit read-only transaction and does not create views, tables,
or other database objects. Each numbered `SELECT` can later be copied into one dashboard
panel.

The next analytical step is the explainable
[Vulnerability Priority Queue](docs/vulnerability-prioritization.en.md). Its standalone
read-only query is in `analytics/vulnerability_priority_queue.sql` and combines CISA KEV,
current and seven-day EPSS signals, and NVD CVSS without claiming organisational exposure.
The same dashboard also uses `analytics/vulnerability_priority_summary.sql`,
`analytics/rising_epss_watchlist.sql`, and `analytics/ransomware_related_kev.sql` for its
summary, rising-risk watchlist, and ransomware-related KEV cards.

The read-only Data Quality & Reliability dashboard starts with
`analytics/data_quality_source_freshness.sql`. It reports one row per source and uses
the NVD durable coverage checkpoint, the last normalized CISA catalog update, and the
latest EPSS score date as source-specific freshness signals.
`analytics/data_quality_epss_missing_dates.sql` checks the latest 90 covered EPSS dates
for internal gaps; trailing unpublished dates remain the responsibility of the freshness
query. `analytics/data_quality_epss_summary_consistency.sql` recalculates retained EPSS
detail aggregates and compares them with their daily summaries.
`analytics/data_quality_cross_source_coverage.sql` reports directional CVE overlap among
CISA KEV, NVD, and the latest EPSS score date without treating normal source differences
as automatic failures. `analytics/data_quality_invalid_value_counts.sql` checks normalized
identifiers, ranges, date ordering, required CISA text, and EPSS aggregate invariants.
`analytics/data_quality_raw_artifact_health.sql` checks raw manifest invariants and reports
retained invalid responses separately from metadata corruption. These queries do not
create database objects or modify application data.

`analytics/data_quality_epss_daily_volume.sql` provides the 90-day EPSS record-count
series, a previous-seven-day baseline, and explicit 5% warning / 20% critical deviation
signals for the Data Quality & Reliability volume chart.

`analytics/data_quality_overall_status.sql` combines eight non-informational health
signals into the dashboard's read-only Overall Status KPI. Cross-source coverage is
excluded from this status because source scope differences are not automatic failures.
`analytics/data_quality_freshness_issues.sql` returns the number of NVD, CISA KEV, and
EPSS sources currently at WARNING or CRITICAL freshness for a scalar KPI card.
`analytics/data_quality_missing_epss_dates_kpi.sql` returns the internal gap count for
the latest 90 covered EPSS dates as a scalar KPI; source publication lag remains covered
by the separate freshness checks.
`analytics/data_quality_integrity_issues.sql` returns the combined normalized-value,
EPSS summary-consistency, and raw-manifest rule violation count for the final scalar KPI.

The read-only Vulnerability Search dashboard uses one required free-text filter across
five cards in `analytics/vulnerability_search_*.sql`. It searches CVE IDs and descriptive
NVD/CISA fields, then enriches the matched set with current EPSS without scanning the
large EPSS history table. Setup and click-through instructions are in
[`docs/vulnerability-search.md`](docs/vulnerability-search.md).

For a CISA-only Git history backfill, use yearly outer windows to reduce GitHub API calls. `THREATFLOW_GITHUB_TOKEN` is optional but recommended for authenticated rate limits:

```sh
uv run --env-file .env threatflow-backfill-range --sources cisa --start 2022-01-01 --end 2026-11-03 --interval-days 366 --checkpoint data/cisa-full-backfill.json
```

Each commit is checkpointed in `raw_artifacts` as soon as its validated snapshot is stored. Airflow retries and controller restarts skip completed commit SHAs inside a partially completed yearly window. A malformed or truncated HTTP 200 response is retained as raw evidence and downloaded again up to `THREATFLOW_HTTP_RETRIES` times. If the same historical revision remains invalid, it is recorded as `git_history_invalid` and skipped so a transient malformed commit in the official repository does not block later valid history.

Build the normalized change history from already downloaded valid snapshots without another network request:

```sh
uv run --env-file .env threatflow-build-cisa-changes
```

Or rebuild with the same one-shot container runtime:

```sh
docker compose run --rm threatflow-cli rebuild-cisa-changes
```

`cisa_kev_changes` stores a `baseline` event for every CVE in the first available Git snapshot, then only `added`, `modified`, and `removed` events. `changed_fields`, `previous_values`, and `current_values` are JSONB. Rebuilding is atomic and idempotent: the derived table is replaced in one transaction while immutable raw snapshots remain unchanged.

`cisa_daily` also maintains this table incrementally. A new validated content hash is compared with the previous valid raw snapshot; its `added`, `modified`, and `removed` events, raw manifest observation, and current-state UPSERT are committed in one database transaction. Daily events use `revision_type=content_sha256`, while Git history uses `revision_type=git_commit`. An identical daily snapshot creates no duplicate events. The full rebuild command remains the recovery tool and reconstructs both Git-derived and daily history from immutable raw files.

An optional one-shot CISA watcher downloads the catalog once, stores the exact bytes in
the existing local content-addressed Raw storage, and creates an in-process
`CisaArtifactObserved` event. A separate handler verifies that the file still matches the
event hash and invokes the same validated ingestion service only when the hash has not
already been processed as a daily snapshot:

```sh
uv run --env-file .env threatflow-watch-cisa
# or with the Compose application runtime
docker compose run --rm threatflow-cli watch-cisa
```

The current event delivery is synchronous and local; no queue or AWS service is required.
The pointer-only event contract can later carry an S3 object identity through SQS without
changing the comparison and ingestion boundary. This is additive functionality:
`cisa_daily` remains enabled as the scheduled recovery
path, and CISA Git history backfill remains unchanged. Concurrent watcher and daily runs
are safe because Raw manifests, change events, and current-state writes are idempotent.
Invalid new content still fails normal CISA validation and does not update current state.
Airflow runs this command automatically through `cisa_watcher_hourly` at
`0 * * * *` UTC. The DAG has `catchup=False`, `max_active_runs=1`, and shares the
one-slot `cisa_api_pool` with `cisa_daily` and CISA backfill, so those HTTP paths
do not run concurrently inside Airflow.

### Operational Runbook

On a failed DAG, inspect the task log in the UI, fix the source or configuration issue, then clear the failed task to rerun it. Task logs include `stage=...` markers for input validation, source fetch, NVD chunks and checkpoints, and completion. They persist in the `airflow_logs` volume and are shared by the scheduler and API server. If the UI is unavailable, find them with `docker compose exec airflow-scheduler find /opt/airflow/logs -type f -name '*.log'` and inspect one with `docker compose exec airflow-scheduler tail -n 200 <log-path>`. HTTP 429 is retried with bounded backoff in the client and then by Airflow; check the NVD API key and allow the source quota to recover. For a missed NVD interval, run a `modified` backfill for the exact dates in chunks no longer than 31 days. For missed EPSS scores, backfill the missing score dates. Check task success and fetched/written counts in logs; a zero `written` count can be valid for an unchanged NVD or CISA snapshot.

Create local custom-format PostgreSQL backups for the application and Metabase databases with:

```sh
docker compose run --rm --no-deps threatflow-cli backup-databases
```

The one-shot CLI reads PostgreSQL connection settings from the existing environment,
uses `metabase` by default for the Metabase database, validates each dump with
`pg_restore --list`, and writes a SHA-256 checksum next to it in `data/backups`.
`--no-deps` keeps this command independent from Airflow, but the PostgreSQL service must
already be running. The command does not back up raw artifacts, Airflow metadata, or the
Metabase encryption key; it also does not upload or delete backups. Keep
`MB_ENCRYPTION_SECRET_KEY` separately in a password manager and copy verified backups
to storage outside the development machine.

Preview database dumps older than the 14-day local retention window with:

```sh
./scripts/report-expired-database-backups.sh
```

This command is read-only: it reports expired `.dump` files and their associated
checksums but never deletes them. Override the reporting window with
`THREATFLOW_BACKUP_RETENTION_DAYS` or the directory with
`THREATFLOW_BACKUP_DIR` in the shell.

Run bounded Airflow cleanup from an external scheduler (for example, weekly cron) after taking the normal database backup:

```sh
docker compose --profile maintenance run --rm airflow-maintenance
```

This keeps Airflow task metadata and local task logs for 90 days and XCom rows for 30 days. Override the database windows with `THREATFLOW_AIRFLOW_METADATA_RETENTION_DAYS` and `THREATFLOW_AIRFLOW_XCOM_RETENTION_DAYS`; the metadata setting also controls the log-file window. The command permanently removes expired operational data and does not touch application tables, immutable raw artifacts, or Docker volumes. NVD and CISA normalized current-state rows and all immutable raw artifacts are retained indefinitely.

Verify application rows in PostgreSQL:

```sql
SELECT count(*), max(last_modified) FROM nvd_cves;
SELECT count(*), max(date_added) FROM cisa_kev_vulnerabilities;
SELECT score_date, count(*) FROM epss_scores GROUP BY score_date ORDER BY score_date DESC LIMIT 7;
SELECT count(*), max(score_date) FROM epss_current;
SELECT * FROM epss_daily_summaries ORDER BY score_date DESC LIMIT 7;
```

Run unit tests with `uv run python -m pytest tests/unit tests/airflow`. Run isolated PostgreSQL integration tests with `uv run python -m pytest tests/integration` while Docker is available. The Airflow image can parse DAGs with `docker compose exec airflow-scheduler airflow dags list-import-errors`.

The adapter is also callable outside Airflow: `uv run python -m threatflow.orchestration daily nvd --start 2025-01-01T00:00:00+00:00 --end 2025-01-02T00:00:00+00:00` or `uv run python -m threatflow.orchestration backfill epss --start 2025-01-01 --end 2025-01-07`. The standalone command uses the same application services.

### Completeness and outage recovery

Apply the application migration before enabling the updated NVD DAG: `docker compose --profile migrate run --rm threatflow-migrate`. NVD daily stores the last successfully covered modification timestamp in the application PostgreSQL `ingestion_checkpoints` table. It resumes there after downtime, splits long gaps into 120-day requests, and advances the checkpoint only after each successful chunk. A PostgreSQL advisory lock serializes overlapping daily runs. The initial run covers the configured lookback only; for a gap predating the first checkpoint, run a bounded manual `modified` backfill. The checkpoint survives Airflow reinstallation if the application database volume is retained.

CISA rejects empty catalogs, a mismatch with published `count`, and snapshots more than 20% smaller than a stored catalog of at least 20 rows. EPSS gzip headers publish a score date and model version but no record count. Ingestion requires conservative date-era minimums (2021: 50k, 2022: 75k, 2023: 100k, 2024: 130k, 2025: 160k, 2026 onward: 180k), plus at least 80% of the previous stored day's count. These thresholds should be reviewed when source coverage changes. Both validations fail before upsert.

For image-level verification, run `docker compose config -q`, start the services as above, then run `docker compose exec airflow-scheduler airflow dags list-import-errors` and the DAG contract test inside the Airflow image. Run `pytest tests/integration` with Docker access before relying on PostgreSQL idempotency.
