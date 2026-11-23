# ThreatFlow weekly status — Week 1

**Status: Green (self-rated)**

The Week 1 milestone, **Data and design validated**, is complete. The problem, intended user,
MVP, source data, target outputs, architecture, data model, reliability approach, and technical
feasibility have all been validated with project evidence.

**Done last week:**

- Defined the problem and intended user: ThreatFlow helps vulnerability-management, SOC, and
  threat-intelligence analysts prioritise CVEs by combining NVD severity and context, CISA KEV
  confirmed exploitation, and FIRST EPSS probability and trend. The agreed MVP is an
  explainable investigation queue; organisation-specific exposure and automated remediation
  are explicitly out of scope. Evidence: [capstone report](capstone-report.md) and
  [prioritisation policy](vulnerability-prioritization.en.md).
- Investigated the actual NVD, CISA KEV, and EPSS sources, including access method, structure,
  grain, update pattern, quality risks, missing or nullable enrichment, duplicate keys,
  completeness risks, and historical limitations. Evidence:
  [dataset assessment](dataset-assessment.md) and [data catalog](data-catalog.md).
- Designed the end-to-end flow and the purpose of Raw/Bronze, Silver, Gold, control, and serving
  components; documented the expected grains and the transformations needed to build the
  vulnerability priority product. Evidence: [architecture](data-pipeline-treatflow.md),
  [data model](data-model.md), and
  [commit c07de57](https://github.com/NataliaGurevich/threatflow-platform-capstone/commit/c07de572551d042660f5dda1693403faaf675012).
- Defined initial reliability decisions: source-specific validation, fail-closed handling of
  incomplete inputs, immutable Raw evidence, business-key uniqueness, idempotent reruns,
  incremental NVD/EPSS processing, bounded commits, lineage, and explicit recovery/backfill.
  Evidence: [failure and recovery demonstration](failure-recovery-demo.md) and
  [governance](governance.md).
- Validated feasibility with fixture-based pipeline tests and a reproducible capstone demo that
  does not call production APIs or modify development data. Evidence:
  [`scripts/run-capstone-demo.sh`](../scripts/run-capstone-demo.sh).
- Repository: [ThreatFlow on GitHub](https://github.com/NataliaGurevich/threatflow-platform-capstone).
  A dedicated PR and project board have not been created yet.

**This week's goals (max 3):**

1. Remove the generated Terraform plan from published Git history and add automated lint/unit-test
   CI.
2. Consolidate implementation evidence for ingestion, incremental processing, quality gates,
   idempotent reruns, and recovery into one reproducible demonstration.
3. Prepare the 20-minute presentation with the architecture, data-quality decisions, and real
   dashboard evidence.

**Blockers / help needed:**

- A generated Terraform plan is removed from the current index and covered by `.gitignore`, but
  it still exists in an older commit in the published history. The history must be cleaned and
  the plan reviewed for sensitive values before the repository is considered publication-safe.
- Coach guidance would help confirm the expected balance between design/reliability evidence and
  live dashboard demonstration in the final presentation.

**Questions for coaches:**

- Does the proposed MVP have the right boundary: prioritisation and investigation, but no claim
  of organisation-specific vulnerability without asset inventory?
- Is the current evidence of actual data exploration and source-specific limitations sufficient
  for the Week 1 milestone?
- For the final assessment, should the strongest emphasis be on reliability and recovery or on
  analytical findings and dashboard usability?

**This week's milestone deliverable:**
[Week 1 — Data and design validated](https://github.com/NataliaGurevich/threatflow-platform-capstone/blob/main/docs/capstone-report.md)
