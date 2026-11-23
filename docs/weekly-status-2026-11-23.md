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

1. **CI/CD:** add a GitHub Actions pipeline for linting, unit tests, Docker Compose validation,
   and Terraform validation on every pull request.
2. **Refactoring:** simplify duplicated code and strengthen module boundaries while preserving
   the existing ingestion, Silver, Gold, and orchestration behaviour.
3. **Tests:** expand regression and integration coverage for validation failures, idempotent
   reruns, incremental processing, and recovery across the main pipeline stages.

**Blockers / help needed:**
-

**Questions for coaches:**
-

**This week's milestone deliverable:**
[README](https://github.com/NataliaGurevich/threatflow-platform-capstone/blob/main/README.md)
