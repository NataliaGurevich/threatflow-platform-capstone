# ThreatFlow weekly status — 23 November 2026

**Status: Amber (self-rated)**  
The main AWS Gold-to-dashboard flow is implemented and the repository is clean and testable,
but publication to GitHub and final end-to-end presentation evidence are still pending.

**Done last week:**

- Implemented the scheduled AWS Gold pipeline and operational visibility, including the
  expanded CloudWatch dashboards (`72842e9`).
- Added Athena views and an automated view-deployment CLI (`c4007e9`, `024d8f1`).
- Added the Athena/Metabase connection infrastructure, dashboard SQL, CVE drill-through, and
  supporting documentation (`d417342`, `0fb0793`, `0823d5c`).
- Milestone evidence: [Athena Gold validation](athena-gold-validation.md),
  [Athena views for Metabase](athena-metabase-views.md), and
  [Vulnerability Priority Overview](metabase-vulnerability-priority-overview.md).
- PRs / project board: not created yet because this local repository does not have a GitHub
  remote configured. The commit hashes above can be replaced with GitHub links after the first
  push.

**This week's goals (max 3):**

1. Publish the repository to GitHub and add CI for lint and unit tests.
2. Capture final evidence for the scheduled Glue job, Catalog partition registration, Athena
   views, Metabase dashboards, and CloudWatch monitoring.
3. Prepare and rehearse the 20-minute capstone presentation using real pipeline and dashboard
   screenshots.

**Blockers / help needed:**

- A GitHub repository/remote and its visibility policy still need to be selected.
- Final AWS checks require an active deployment session with the intended account and region;
  no production credentials or environment-specific secrets will be committed.
- Coach feedback is requested on the amount of implementation detail expected in the final
  presentation versus the end-user story and live dashboard demonstration.

**Questions for coaches:**

- Is reconstructed historical Gold acceptable when it is explicitly labelled and the
  incomplete NVD-history limitation is visible in the data product?
- For the final assessment, should the presentation prioritise recovery/idempotency evidence or
  deeper Metabase drill-through and analytical findings?
- Is repository-level CI sufficient for the capstone, or is a fully automated AWS deployment
  expected as part of the milestone?

**This week's milestone deliverable:**
[ThreatFlow capstone report](capstone-report.md)
