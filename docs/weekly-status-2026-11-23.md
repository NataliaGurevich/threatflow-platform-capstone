# ThreatFlow weekly status — Week 1

**Status: Green (self-rated)**

The Week 1 milestone, **Data and design validated**, is complete. The problem, intended user,
MVP, source data, target outputs, architecture, data model, reliability approach, and technical
feasibility have all been validated with project evidence.

**Done last week:**

- Defined the problem, intended users, MVP, and scope; analysed the NVD, CISA KEV, and EPSS data.
- Designed the Bronze–Silver–Gold pipeline, data model, validation, idempotency, and recovery
  approach.
- Validated feasibility with tests and a reproducible demo; documented the project in
  [GitHub](https://github.com/NataliaGurevich/threatflow-platform-capstone).

**This week's goals (max 3):**

1. **CI/CD:** add a GitHub Actions pipeline for linting, unit tests, Docker Compose validation,
   and Terraform validation on every pull request.
2. **Refactoring:** simplify duplicated code and strengthen module boundaries while preserving
   the existing ingestion, Silver, Gold, and orchestration behaviour.
3. **Tests:** expand regression and integration coverage for validation failures, idempotent
   reruns, incremental processing, and recovery across the main pipeline stages.

**Blockers / help needed:**

—

**Questions for coaches:**

—

**This week's milestone deliverable:**
[README](https://github.com/NataliaGurevich/threatflow-platform-capstone/blob/main/README.md)
