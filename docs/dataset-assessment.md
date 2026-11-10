# ThreatFlow dataset assessment

## Decision

ThreatFlow uses three complementary public datasets rather than treating them as
interchangeable sources. **NVD is the hero dataset** because it supplies the broad CVE
universe, mutable vulnerability records, severity, weakness and reference data, and a
genuine incremental-ingestion problem. **CISA KEV is the fallback dataset** because it is
small, openly licensed, operationally meaningful and can independently support a useful
confirmed-exploitation product. FIRST EPSS is retained as an enrichment and time-series
dataset because it adds exploitation probability but is not a complete risk score.

The selected product joins all three by CVE ID to answer: **which vulnerabilities should a
vulnerability analyst investigate first, if the affected products are present in the
organisation?** The fallback product is a CISA KEV investigation queue enriched with the
available NVD or EPSS data; it remains useful when one enrichment source is unavailable.

## Evaluation criteria

| Area | NVD CVE API 2.0 — hero | CISA KEV — fallback | FIRST EPSS — enrichment |
| --- | --- | --- | --- |
| Owner and access | NIST NVD; public HTTPS API; optional API key improves request allowance | CISA canonical catalog plus official `cisagov/kev-data` Git mirror | FIRST EPSS SIG; daily CSV, API and historical archive; no registration required |
| Row meaning | One returned item represents the current NVD view of one CVE at response time | One item represents one CVE in the current Known Exploited Vulnerabilities catalog | One row represents one CVE score on one source score date |
| Useful fields | CVE ID, descriptions, publication/modification time, CVSS, CWE and references | CVE ID, vendor/project, product, dates, required action and ransomware context | CVE ID, EPSS probability and percentile |
| Change semantics | New records and later modifications; synchronize with `lastModStartDate`/`lastModEndDate` | Complete current snapshot, not a delta; official Git history can reconstruct revisions | Complete daily score set; every score may change on the next source date |
| History | Published/modified API windows and CVE change history; the client must retain its own Raw responses | Canonical feed has no inline history; official Git mirror retains revisions | Daily archives are available from 2021-04-14 |
| Access constraints | Pagination, throttling, transient failures and a maximum 120-day API date range | Small full-feed download; GitHub API limits apply to history traversal | API is intended for lookup, not bulk mirroring; daily CSV/archive is the correct batch interface |
| Quality risks | Nullable or delayed enrichment, multiple CVSS versions, mutable records, pagination changes | Empty/truncated snapshot, declared-count mismatch, unexpected shrinkage, source schema change | Wrong source date, truncated gzip/CSV, duplicates, range violations, incomplete daily population and model-version shifts |
| Identifying new/change data | CVE `lastModified` plus durable successful-window checkpoint | Content SHA-256/catalog revision; diff consecutive valid snapshots | `(cve_id, score_date)` and latest successfully published source date |
| Governance | Public US-government vulnerability information; attribution and source terms still apply | Git mirror is CC0 1.0; CISA/DHS names and logos must not imply endorsement | Published freely; FIRST requests attribution in publications/products |
| Sensitive data | No personal or organisational asset data in the selected projection | No personal data in the selected catalog fields | No personal data in the published scores |
| Suitability | Best source for a broad searchable CVE universe and for demonstrating incremental mutable ingestion | Strong signal of confirmed exploitation and actionable remediation context | Adds probability and trend, reducing reliance on technical severity alone |
| Missing context | Does not say whether a product is installed, exposed, critical or patched; CVSS is not organisational risk | Catalog membership does not prove presence in a particular organisation | Not impact, exposure or complete risk; score changes can reflect model/input changes |
| Feasibility | Feasible with bounded windows, pagination, throttling and local PostgreSQL | Highly feasible because the catalog is small and snapshot based | Feasible with daily compressed files, bounded retained detail and permanent summaries/Raw files |
| Source outage response | Retry; do not advance checkpoint; recover gaps with `modified` backfill | Keep last valid current state; daily reconciliation and Git history remain recovery paths | Fail the date; retry after publication; backfill the exact missing date |

## Why the hero and fallback were selected

NVD is the hero because it demonstrates the largest range of core data-engineering skills:
pagination, incremental windows, mutable records, stale-update protection, recovery and a
large current dataset. Its main disadvantage is operational complexity and incomplete or
delayed enrichment for some CVEs.

CISA KEV is the fallback because it can still answer a narrower but valuable question:
which vulnerabilities have confirmed exploitation and what remediation action does CISA
recommend? Its full-snapshot semantics are simple enough to finish reliably within a
capstone, while content hashes and Git snapshots still demonstrate idempotency and history.

EPSS was not selected as the standalone hero because exploitation probability without
impact or environment context is not a complete prioritisation product. It is valuable as
a daily time series and an enrichment signal combined with NVD and CISA KEV.

## Assumptions and limitations

- CVE ID is the cross-source correlation key, but source coverage is not identical; a
  missing match is not automatically a data-quality failure.
- ThreatFlow provides an investigation queue, not proof that an organisation is vulnerable.
- The current model has no asset inventory, installed versions, exposure, business
  criticality, compensating controls or remediation status.
- The project retains the latest NVD and CISA state in serving tables. Exact Raw responses,
  CISA change events and retained EPSS daily rows/summaries provide the available history.
- Source schemas, publication schedules and model versions may change. Raw preservation and
  explicit validation make reprocessing possible but do not eliminate upstream risk.

## Authoritative references

- [NVD CVE API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD data feeds and API synchronization guidance](https://nvd.nist.gov/vuln/data-feeds)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Official CISA KEV Git mirror and update semantics](https://github.com/cisagov/kev-data)
- [CISA KEV CC0 licence](https://github.com/cisagov/kev-data/blob/develop/LICENSE)
- [FIRST EPSS data access and historical archive](https://www.first.org/epss/data)
- [FIRST EPSS interpretation and limitations](https://www.first.org/epss/faq)

