# ADR 0002: Independent event-driven EPSS Silver processing

- Status: Application, AWS storage, and queues deployed; image Terraform prepared, event wiring pending
- Date: 2026-11-12

## Context

ThreatFlow keeps a local Raw copy and local PostgreSQL ingestion tables while replicating only
validated artifacts to S3 Bronze. The AWS Bronze-to-Silver path must remain operationally
independent of the local PostgreSQL database and must not require `raw_artifact_id`.

S3 notifications can be duplicated and are not ordered. A failed transformation must not expose
a partially committed Silver partition, and replaying the same event must be safe.

## Decision

The accepted AWS flow is:

```text
validated local ingestion -> versioned S3 Bronze -> SQS -> Lambda -> S3 Silver
                                                   `-> DLQ
```

The Lambda handler treats the versioned S3 object as its complete input contract. It requires the
content-addressed EPSS key and object version, verifies the downloaded bytes and S3 metadata,
derives `score_date` from the source header, and reuses the application parser, completeness gate,
and Parquet transformer. It never reads or writes PostgreSQL.

Silver uses one partition per EPSS source date. Parquet is conditionally published first and a
JSON manifest is conditionally published last. The manifest is the commit marker. Duplicate
events reuse a matching committed partition; a different source SHA-256 for the same date fails
without overwriting the existing partition. SQS partial batch failures provide bounded retries
and a future DLQ-based recovery demonstration.

The application handler and fixture tests are implemented. Terraform now defines the Silver
bucket, a Standard source queue, and a dedicated DLQ with bounded redrive. Lambda packaging and
the private ECR repository are implemented with an ARM64 Python 3.12/PyArrow container image.
Lambda IAM/function configuration, AWS invocation, the S3 notification, SQS event-source mapping,
and CloudWatch alarms remain deliberately separate deployment slices.

## Consequences

- Local Raw storage and PostgreSQL continue to support the reproducible local platform.
- A local PostgreSQL outage cannot block or corrupt an already emitted AWS Silver transformation.
- AWS processing must revalidate Bronze rather than trust local database metadata.
- `epss_silver_request.py` is not the automatic trigger contract; it remains an audit/manual replay
  helper.
- S3, SQS, Lambda, logs, and audit telemetry add request, compute, and retention costs that must be
  reviewed before deployment.
- The S3 notification must be restricted to `bronze/source=epss/*.csv.gz`, and Silver output must
  not match that prefix, preventing recursive invocation.
