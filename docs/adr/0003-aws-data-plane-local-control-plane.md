# ADR 0003: AWS data plane with a local control plane

- Status: Accepted
- Date: 2026-11-24

## Context

The earlier rollout kept two operational persistence paths: local Raw plus PostgreSQL application
tables, followed by optional S3 replication. That was useful while AWS was experimental, but it
duplicated state, checkpoints, recovery procedures, and success semantics. The deployed Silver
and Gold paths already use S3 commit manifests as their durable contracts.

The project still needs a local Airflow runtime, local Metabase metadata, credential-free tests,
and temporary filesystem space used by the same transformations that run in Lambda and Glue.
Those are development and control-plane needs, not a second data plane.

## Decision

S3 is the only runtime persistence layer for pipeline data:

- accepted source bytes are written directly to immutable, content-addressed S3 Bronze objects;
- source payloads that fail structural or completeness gates are written to
  `bronze/_quarantine/` and the task fails;
- S3/SQS/Lambda publish committed Silver Parquet and manifests;
- Glue publishes committed Gold Parquet and registers exact Catalog partitions;
- the NVD modified-window checkpoint is a conditional S3 control object;
- backfill resumption uses deterministic Airflow DAG-run IDs and the Airflow API as its source of
  truth;
- CISA backfill means one current catalog synchronization; the separate hourly watcher and Git
  revision history path are removed;
- local-to-S3 replication and its configuration switch are removed.

Local PostgreSQL remains because Airflow and Metabase require metadata databases. Existing local
application tables, Docker volumes, and files under `data/` are not automatically deleted. Local
fixtures, stubbed AWS clients, `tmp_path`, and bounded `/tmp` transformation output remain part of
the test and AWS runtime implementation.

## Consequences

- A successful Airflow ingestion has one durable meaning: accepted Bronze exists in AWS.
- PostgreSQL availability cannot decide pipeline data correctness or NVD recovery coverage.
- Running ingestion locally requires short-lived AWS credentials and configured Bronze/Silver
  buckets; unit tests do not.
- Rejected upstream bytes remain available for investigation without triggering Silver.
- Previously created local business data is retained until an operator approves a separate,
  recoverable cleanup plan.
- Historical documentation describing dual-write remains useful as rollout history but is no
  longer the current runtime contract.
