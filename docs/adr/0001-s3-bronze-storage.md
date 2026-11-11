# ADR 0001: Pluggable Bronze storage with Amazon S3

- Status: Accepted
- Date: 2026-11-10

## Context

ThreatFlow currently preserves exact NVD, CISA KEV, and EPSS response bytes on the local
filesystem before parsing. The capstone needs a small AWS extension without coupling source
ingestion to boto3 or making the existing local demo depend on AWS credentials.

Raw storage must preserve the existing invariants: exact bytes, SHA-256 identity, immutable
publication, global deduplication per source and hash, failure propagation, and the ability to
read an artifact for replay or CISA change derivation.

## Decision

Ingestion depends on the `RawArtifactStore` protocol. `LocalRawArtifactStore` remains the
default. `S3RawArtifactStore` implements the accepted bucket contract behind the same protocol;
selecting it requires explicit settings and does not deploy infrastructure.

The S3 object key will be deterministic and content-addressed:

```text
bronze/source=<source>/sha256=<sha256>.<extension>
```

For example:

```text
bronze/source=epss/sha256=a1b2c3....csv.gz
```

Acquisition time, request interval, source revision, row count, and run ID belong in the
PostgreSQL manifest and selected S3 object metadata rather than in the object key. Therefore,
observing the same source bytes on another date reuses the same logical object.

`raw_artifacts` represents that logical source/hash identity. Physical copies are separate rows
in `raw_artifact_locations`, with at most one current verified locator per backend. A single
artifact may therefore remain available locally while an independently verified S3 copy is
added, enabling a reversible rollout without duplicating its observation lineage.

Terraform will manage the AWS resources. The initial module will create one development Bronze
bucket with public access blocked, ACLs disabled, versioning, default encryption, TLS-only
access, lifecycle rules, and least-privilege IAM. Terraform state, credentials, and personal
variable files will not be committed.

The rollout sequence is:

1. Introduce the storage protocol and preserve local behavior.
2. Add and statically validate the Terraform module without applying it.
3. Add the S3 adapter and unit tests with stubbed AWS calls. **Complete.**
4. Review `terraform plan`, then explicitly approve creation of development resources.
5. Reconcile hashes and sizes for EPSS before rolling out CISA and NVD.

## Consequences

- Local development and the capstone demo continue without AWS access.
- Source ingestion does not import boto3 or Terraform-specific code.
- Storage failures continue to fail ingestion before normalized database writes.
- CISA replay reads through the storage contract instead of directly opening a local path.
- Migration `0008_raw_artifact_locations` keeps the legacy `storage_path` column for
  compatibility, creates the one-to-many locations table, and backfills existing paths as
  `local` locations.
- Existing local manifest rows are not uploaded or rewritten automatically. Reconciliation is
  required before switching an ingestion source; backend-specific reads fail clearly if the
  requested location has not been verified.
- A source/hash key favors idempotency over date-based browsing. Acquisition dates remain
  queryable in PostgreSQL; later analytical datasets may use date partitions independently.

## Rejected alternatives

- Putting AWS SDK calls inside Airflow DAGs: this violates the orchestration boundary.
- Running local and S3 implementations as separate ingestion pipelines: this risks divergent
  parsing and duplicate normalized writes.
- Including acquisition date in the S3 key: repeated identical payloads would create redundant
  objects and conflict with the current global source/hash deduplication rule.
- Maintaining both CDK and Terraform: two IaC implementations add no capstone value.
