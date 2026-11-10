# ThreatFlow capstone presentation script

## Recommended format

Target duration: **8 minutes**, followed by questions. Keep the local stack running before
the presentation. Do not run ingestion, migrations, backfills or external API requests live.
The live portion uses only the verified demo command and read-only analytical SQL.

## Before the presentation

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
./scripts/run-capstone-demo.sh --with-running-stack
```

Keep these pages/files ready:

1. `docs/capstone-report.md`
2. `docs/data-model.md`
3. `docs/failure-recovery-demo.md`
4. Metabase Vulnerability Priority Queue dashboard
5. Terminal at the completed demo output

Do not depend on live public APIs. If the UI is unavailable, show the read-only SQL results
from the terminal.

## 0:00–0:45 — Problem and user

**Show:** title and one-sentence problem statement.

**Say:**

> ThreatFlow is a cybersecurity data engineering pipeline for a vulnerability-management,
> SOC or threat-intelligence analyst. It answers: which CVEs should be investigated first,
> if the affected products are present in the organisation? The project does not claim that
> an organisation is vulnerable because it does not yet contain asset inventory, exposure or
> remediation status.

Emphasise that the output is an investigation queue, not an automatic remediation decision.

## 0:45–1:45 — Dataset selection

**Show:** the comparison table in `docs/dataset-assessment.md`.

**Say:**

> I assessed three public sources. NVD is the hero dataset because it provides the broad CVE
> universe and a real incremental-ingestion challenge: records are modified after initial
> publication. CISA KEV is the fallback because it is a small, operationally useful catalog
> of confirmed exploitation. EPSS is a daily enrichment that estimates exploitation
> probability. The sources are complementary: CVSS is severity, EPSS is probability, and
> KEV is confirmed exploitation.

Mention one limitation per source:

- NVD enrichment can be nullable or delayed;
- CISA is a complete current snapshot rather than a historical API;
- EPSS is not impact or organisational risk.

## 1:45–2:45 — Architecture

**Show:** the implemented architecture diagram in `docs/capstone-report.md`.

**Say:**

> Airflow schedules source-specific Python services. The DAGs contain orchestration rather
> than HTTP or SQL logic. Exact source bytes are stored before parsing in immutable,
> content-addressed Raw storage. PostgreSQL stores current, retained history and operational
> control data. Read-only analytical SQL supplies Metabase. The AWS lakehouse is a future
> evolution, not something I claim is already deployed.

Point out why Raw and normalized storage are separate: replay, audit and parser changes.

## 2:45–3:45 — Data model and incremental processing

**Show:** the ER diagram in `docs/data-model.md`.

**Say:**

> Each source has different change semantics. NVD uses modification windows and advances a
> durable checkpoint only after a complete successful window. CISA uses full snapshots and
> exact-content hashes; consecutive valid snapshots produce added, modified and removed
> events. EPSS is keyed by CVE plus source score date, while a separate current table supports
> fast joins. Replays use database UPSERTs and cannot create duplicate business keys.

Call out two safeguards:

- an older NVD record cannot overwrite a newer version;
- an older EPSS backfill cannot regress the current score.

## 3:45–4:45 — Data quality and recovery

**Show:** `docs/failure-recovery-demo.md`.

**Say:**

> A syntactically valid response is not automatically trustworthy. CISA rejects empty,
> count-mismatched and implausibly shrinking snapshots. EPSS validates source date, ranges,
> duplicates and conservative completeness thresholds. NVD validates pagination totals and
> does not advance coverage after a partial traversal. Errors propagate to Airflow as failed
> tasks, normalized writes roll back, and Raw evidence remains available for replay.

Concrete example:

> If an EPSS historical file contains only one valid-looking row, ThreatFlow fails before
> opening the database. A later retry of the correct date is safe because the business key is
> CVE plus score date.

## 4:45–6:15 — Live demonstration

**Show:** a terminal containing the already completed output of:

```bash
./scripts/run-capstone-demo.sh --with-running-stack
```

Narrate the important lines:

1. Ruff and unit/orchestration tests pass.
2. Disposable PostgreSQL integration tests pass.
3. Airflow reports no DAG import errors.
4. PostgreSQL answers the priority and data-quality queries.

> The exact counts change as public data changes. In the verified run on 10 November 2026,
> the queue contained 4,576 active candidates: 1,024 P1, 749 P2, 2,791 P3 and 12 WATCH. The
> overall data-quality status was OK across eight evaluated signals, with no warnings or
> critical signals.

Do not spend presentation time waiting for Testcontainers; show completed output. Run the
command live only if explicitly requested.

## 6:15–7:15 — Data product

**Show:** Metabase priority queue or the SQL result.

**Say:**

> The final product is explainable. P1 means confirmed KEV plus high EPSS or known ransomware
> context. P2 covers other confirmed KEV entries. P3 highlights high or critical CVSS with
> high EPSS outside KEV. WATCH identifies a material seven-day EPSS increase. These are
> documented project rules, not a universal risk standard.

Open one example row and explain which source contributes each visible signal.

## 7:15–8:00 — Engineering judgement and next steps

**Say:**

> I deliberately kept the implemented capstone reproducible on Docker Compose instead of
> adding distributed technology without evidence. The next scale step is moving Raw and
> historical analytics to S3 and Parquet or Iceberg, while keeping PostgreSQL for current
> serving. Before that migration I would complete a measured restore drill and add asset
> inventory so the product can make organisation-specific prioritisation claims.

Close with:

> The result is not just a pipeline that ran once. It is a replayable, idempotent and testable
> data product with explicit source semantics, recovery paths and user-facing output.

## Five-minute fallback

- Problem and datasets: 60 seconds.
- Architecture and model: 75 seconds.
- Quality and recovery: 60 seconds.
- Completed demo output and product: 75 seconds.
- Limitations and next step: 30 seconds.

Skip live test execution and show one priority example.

## Likely questions

### Why three sources?

NVD supplies technical context/severity, CISA supplies confirmed exploitation, and EPSS
supplies probability/trend. None alone answers the user question as well.

### Why PostgreSQL instead of a warehouse?

It supports transactional UPSERTs, low-latency joins and local reproducibility at the current
scale. Measured history growth justifies columnar storage as a next step, not a prerequisite.

### Why no foreign keys between source tables?

The publishers have different scopes and timing. Cross-source absence is missing context,
not necessarily invalid data.

### How do you prevent duplicates?

Raw artifacts are unique by source/hash; normalized tables use database business keys and
UPSERTs; CISA changes are unique by revision/CVE; repeated Airflow runs are safe.

### What happens after an outage?

NVD uses its durable checkpoint and modified backfill. EPSS backfills exact missing score
dates. CISA keeps the last valid state, with daily reconciliation and Git history recovery.

### Is EPSS a risk score?

No. It estimates exploitation probability and must be combined with impact and environment
context.

### What would you build next?

First a measured backup/restore drill and a small asset-inventory model. Then S3 Raw and
columnar historical analytics if measurements justify the migration.

## Presentation safety checklist

- [ ] Docker services are healthy before screen sharing.
- [ ] No `.env`, passwords, API keys or database DSNs are visible.
- [ ] No live backfill or public API request is required.
- [ ] Completed demo output is available as fallback.
- [ ] The AWS diagram is labelled target/future state.
- [ ] The asset-inventory limitation is stated before prioritisation.
- [ ] Skipped tests are described as NOT VERIFIED, never as passing.

