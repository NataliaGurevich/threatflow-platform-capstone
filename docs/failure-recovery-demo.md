# Failure and recovery demonstration

## Purpose

This demonstration proves that ThreatFlow is repeatable and fails safely. It uses local
fixtures and disposable PostgreSQL containers; it does not call NVD, CISA, FIRST, GitHub or
AWS and does not mutate the development database.

## One-command verification

From the repository root:

```bash
./scripts/run-capstone-demo.sh
```

The command performs:

1. Ruff static checks.
2. Unit tests for exact Raw bytes, duplicate storage, corrupt payload rejection, incomplete
   source detection and watcher retry behavior.
3. PostgreSQL Testcontainers tests for idempotent upserts, stale-update prevention,
   transaction rollback and replay. These are skipped with a clear `NOT VERIFIED` result if
   Docker is unavailable.
4. Airflow-independent orchestration tests.
5. Docker Compose configuration validation.

To also show the analytical product using an already-running local stack:

```bash
./scripts/run-capstone-demo.sh --with-running-stack
```

This mode executes only read-only SQL against the configured application database. It does
not start/stop services, run migrations, download feeds or modify rows. It also verifies
that the running Airflow container reports no DAG import errors.

## Scenario A — immutable and idempotent Raw storage

**Action:** store identical exact bytes twice, then store changed bytes.  
**Expected:** the retry resolves to the same path and creates no second artifact; changed
bytes create a different SHA-256/path. A simulated atomic-publish failure leaves neither a
partial JSON file nor a temporary file.

Evidence:

- `tests/unit/test_raw_storage.py`
- unique manifest key `(source, sha256)`

## Scenario B — invalid CISA snapshot

**Action:** watcher receives malformed content or a catalog with an empty array/count
mismatch.  
**Expected:** exact Raw bytes remain available, validation raises an error, normal ingestion
does not report success and current KEV state is unchanged. A retry with a valid new hash
reuses the already downloaded bytes and executes the normal transactional ingestion path.

Evidence:

- `test_new_invalid_snapshot_propagates_ingestion_failure_but_keeps_raw`
- `test_declared_catalog_count`
- `test_transaction_rollback`
- `test_daily_ingestion_writes_incremental_changes_atomically`

## Scenario C — incomplete EPSS archive and safe replay

**Action:** provide a structurally valid but implausibly small historical archive.  
**Expected:** completeness validation fails before opening the database. Previously committed
dates remain valid. Reprocessing a committed `(cve_id, score_date)` updates rather than
duplicates it, and an older backfill cannot regress `epss_current`.

Evidence:

- `test_incomplete_historical_archive_never_opens_database`
- `test_insert_repeat_update_dates_batch_and_retention`
- `test_current_does_not_regress_and_history_retention_is_inclusive`
- `test_rollback_across_batches`

## Scenario D — NVD pagination/outage recovery

**Action:** simulate a response whose `totalResults` changes after a page has already been
stored.  
**Expected:** ingestion fails after retaining Raw evidence and does not treat the incomplete
traversal as success. Durable coverage advances only after the whole window commits. On
recovery, modified backfill covers the missing interval. An older returned CVE cannot replace
a newer stored `last_modified` version.

Evidence:

- `test_total_change_fails_after_raw_storage`
- `test_pagination_and_duplicate_resolution`
- `test_older_record_cannot_replace_newer_record`
- orchestration/checkpoint regression tests in `tests/airflow/`

## Scenario E — analytical output and trust indicators

With the stack running, the demo displays the priority summary and overall data-quality
status. The expected result is not a fixed row count—the public sources evolve—but the
queries must return successfully and expose freshness/integrity status alongside the
investigation product.

## Scenario F — local-to-S3 reconciliation recovery

**Action:** dry-run a valid local artifact and a same-size artifact with the wrong SHA-256;
then simulate an S3 failure after one prior location has been committed.
**Expected:** dry-run makes no AWS call and reports the corrupt copy; apply mode propagates the
S3 error while preserving the earlier location. A retry can reuse the already-created object,
records only the missing S3 location, and does not increment the logical artifact's
`seen_count`.

Evidence:

- `tests/unit/test_raw_storage_reconciliation.py`
- `test_raw_artifact_can_have_local_and_s3_locations`

## Interpreting results

- `PASS`: command executed and its assertions passed.
- `FAIL`: command executed and found a defect; do not present the demo as successful.
- `NOT VERIFIED`: environmental prerequisite was unavailable, commonly Docker/Airflow.
- A skipped integration test is never evidence that PostgreSQL behavior passed.

