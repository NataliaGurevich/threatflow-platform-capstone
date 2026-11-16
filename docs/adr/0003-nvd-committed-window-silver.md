# ADR 0003: Commit complete NVD windows before Silver transformation

## Status

Accepted and implemented locally. AWS deployment remains subject to a reviewed Terraform plan and
explicit apply approval.

## Context

NVD API results are paginated and queried with two distinct time semantics: `published` uses
`pubStartDate`/`pubEndDate`, while `modified` uses `lastModStartDate`/`lastModEndDate`. One logical
window can therefore produce several content-addressed Bronze page objects. An S3 notification for
an individual page cannot prove that all pages were fetched or identify the window mode and bounds.
Publishing Silver from those notifications could make an incomplete response appear successful.

## Decision

After all pages pass structural, pagination, count, parsing, and duplicate validation, ingestion
publishes one immutable `.window.json` Bronze commit marker. It contains the mode and UTC bounds
plus every page's ordered start index, record count, SHA-256, S3 key, VersionId, and size. Only this
suffix is routed through S3 → SQS → Lambda.

Lambda reads the window and pages by exact VersionId, repeats fail-closed validation, deduplicates
by CVE while preserving the greatest NVD `lastModified`, and writes one immutable Parquet window.
The Silver `_manifest.json` is written last and is the commit marker. Published and modified windows
use separate partitions; overlapping modified recovery windows are valid history.

Reconciliation lists committed Bronze windows and checks for their deterministic Silver manifests.
Dry-run is read-only. Apply enqueues only missing exact-version windows. Orphan pages are reported
by the absence of a window commit and are recovered by retrying source ingestion, not by guessing a
page set.

## Consequences

- Partial NVD pagination cannot silently become committed Silver data.
- Bronze SHA and VersionId lineage is retained at window and page level.
- Duplicate or out-of-order S3/SQS delivery is safe because publication is immutable and idempotent.
- One small extra Bronze object is stored per completed NVD window, with corresponding S3 request,
  SQS, Lambda, ECR, CloudWatch, and log-retention costs.
- Downstream current-state queries must order by source `lastModified`, not acquisition time.
