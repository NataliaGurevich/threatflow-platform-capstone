# ThreatFlow data model

## Model objective

The implemented local model separates immutable evidence, operational coverage, current
serving state, retained history and analytical outputs. It is deliberately smaller than the
target AWS lakehouse: PostgreSQL and local Raw storage are sufficient for the capstone MVP.

```mermaid
erDiagram
    RAW_ARTIFACTS {
        bigint id PK
        string source
        string sha256
        text storage_path
        timestamptz first_acquired_at
        timestamptz last_seen_at
        int seen_count
        string request_mode
        timestamptz requested_start
        timestamptz requested_end
        int record_count
        string source_revision
    }

    RAW_ARTIFACT_LOCATIONS {
        bigint id PK
        bigint artifact_id FK
        string backend
        text uri
        string storage_bucket
        text storage_key
        text storage_version_id
        timestamptz first_recorded_at
        timestamptz last_verified_at
    }

    INGESTION_CHECKPOINTS {
        string source PK
        timestamptz covered_until
    }

    NVD_CVES {
        string cve_id PK
        text description
        timestamptz published
        timestamptz last_modified
        float cvss_score
        string cvss_severity
        jsonb cwe_ids
        jsonb references
    }

    CISA_KEV_VULNERABILITIES {
        string cve_id PK
        text vendor_project
        text product
        date date_added
        date due_date
        string known_ransomware_campaign_use
    }

    CISA_KEV_CHANGES {
        bigint id PK
        string commit_sha
        string revision_type
        timestamptz committed_at
        string cve_id
        string change_type
        jsonb previous_values
        jsonb current_values
    }

    EPSS_SCORES {
        string cve_id PK
        date score_date PK
        float epss_score
        float percentile
    }

    EPSS_CURRENT {
        string cve_id PK
        date score_date
        float epss_score
        float percentile
    }

    EPSS_DAILY_SUMMARIES {
        date score_date PK
        int record_count
        float average_score
        float maximum_score
        int low_risk_count
        int medium_risk_count
        int high_risk_count
    }

    NVD_CVES o|..o| CISA_KEV_VULNERABILITIES : "logical join by cve_id"
    NVD_CVES o|..o| EPSS_CURRENT : "logical join by cve_id"
    CISA_KEV_VULNERABILITIES o|..o| EPSS_CURRENT : "logical join by cve_id"
    CISA_KEV_VULNERABILITIES ||..o{ CISA_KEV_CHANGES : "change history by cve_id"
    EPSS_CURRENT ||..o{ EPSS_SCORES : "latest from retained dates"
    EPSS_DAILY_SUMMARIES ||..o{ EPSS_SCORES : "aggregate by score_date"
    RAW_ARTIFACTS ||--o{ RAW_ARTIFACT_LOCATIONS : "has verified copies"
```

Dotted relationships are logical analytical joins, not database foreign keys. A source may
legitimately publish a CVE before or without another source.

## Table roles and grains

| Layer | Table/storage | Grain | Role |
| --- | --- | --- | --- |
| Raw | Local path or `s3://bucket/bronze/source=<source>/sha256=<sha256>.<ext>` | One exact unique payload per source/hash | Replayable immutable evidence |
| Manifest | `raw_artifacts` | One source/hash | Searchable Raw provenance and observation metadata |
| Location | `raw_artifact_locations` | One artifact/backend | Independently verified local and S3 copies |
| Coverage | `ingestion_checkpoints` | One source | Last completely committed NVD modified-window boundary |
| Current | `nvd_cves` | One CVE | Latest accepted NVD projection |
| Current | `cisa_kev_vulnerabilities` | One CVE | Latest accepted KEV state |
| History | `cisa_kev_changes` | One revision/CVE event | Derived CISA baseline/add/modify/remove history |
| History | `epss_scores` | One CVE/source date | Configurably retained detailed score history |
| Current | `epss_current` | One CVE | Latest accepted EPSS score |
| Aggregate | `epss_daily_summaries` | One source date | Permanent daily EPSS summary |
| Analytical | `analytics/*.sql` | Query-specific | Priority queue, search, trends, freshness and quality results |

## Write invariants

1. Raw exact bytes are persisted before parsing or normalized database writes.
2. `(source, sha256)` and all business keys are idempotent under retry.
3. One logical artifact may have both local and S3 locations; reads never silently cross backend.
4. NVD current state changes only when the incoming `last_modified` is not older.
5. EPSS history is keyed by source date; `epss_current` cannot regress to an older date.
6. CISA accepts only non-empty, structurally valid, count-consistent snapshots and rejects
   implausible shrinkage against an established current table.
7. An incomplete NVD pagination traversal does not advance the coverage checkpoint.
8. CISA omissions do not physically delete current rows.
8. Operational errors roll back normalized writes and propagate to Airflow as failed tasks.

## Analytical model

The main product is a read-only vulnerability priority queue. It builds a CVE universe from
CISA KEV and current EPSS, then left-joins NVD, CISA and recent EPSS signals. Left joins are
intentional: temporarily missing enrichment must not hide a confirmed KEV entry.

The policy produces explainable `P1`, `P2`, `P3` and `WATCH` tiers. It does not materialise
an opaque universal risk score and does not claim organisational exposure. Supporting SQL
provides ransomware context, rising EPSS, vulnerability search and data-quality status.

## Evolution boundary

At current scale PostgreSQL is the serving and analytical store. The documented target can
move immutable Raw to S3 and multi-year history to Parquet/Iceberg while preserving these
business grains and invariants. AWS services are an optional extension, not a prerequisite
for the capstone MVP.

