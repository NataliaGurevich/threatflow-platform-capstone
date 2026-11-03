# ThreatFlow

ThreatFlow is a cybersecurity intelligence data engineering platform for CISA KEV, NVD, and EPSS. Work is being delivered in phases; this foundation establishes configuration, database models, and the initial migration only.

The schema has exactly three application tables: `cisa_kev_vulnerabilities`, `nvd_cves`, and `epss_scores`. NVD retains the latest ingested state per CVE, not every historical version. PostgreSQL 17 runs through Docker Compose with a persistent named volume and health check.

## Raw data storage (Phase 2)

`threatflow.raw_storage.store_raw_artifact` stores original response bytes before parsing or loading. It partitions artifacts by source and acquisition month and names each file with the SHA-256 digest of the exact bytes:

```text
data/raw/
├── cisa_kev/year=2026/month=11/<sha256>.json
├── nvd/year=2026/month=11/<sha256>.json
└── epss/year=2026/month=11/<sha256>.csv.gz
```

Artifacts are immutable: a complete temporary file is atomically published, and an existing identical artifact is reused. Changed bytes have a different digest and produce a separate file. Raw files are excluded from Git; `.gitignore` preserves the directory placeholder.

Configure the storage root with `THREATFLOW_RAW_DATA_DIR` in `.env`; it defaults to `data/raw`. Copy `.env.example` to `.env` and change the value if you want a different local directory. Run unit tests with `uv run python -m pytest`; storage tests use temporary directories and do not connect to PostgreSQL.

## Phase 1 local setup

Install uv, copy `.env.example` to `.env`, set a local PostgreSQL password, and run `uv sync --group dev`. Start the database with `docker compose up -d postgres`, then run `uv run alembic upgrade head`. Migration and PostgreSQL integration verification must use a dedicated isolated database.

## CISA KEV ingestion (Phase 3)

`threatflow.ingestion.cisa_client` downloads the complete official CISA KEV JSON with HTTPX, explicit timeouts, and bounded retries. `cisa_ingestion` timestamps acquisition, stores the exact response bytes through the Phase 2 immutable `store_raw_artifact` service, validates the catalog with Pydantic, then bulk upserts records through PostgreSQL `ON CONFLICT (cve_id) DO UPDATE`. The transaction is atomic; catalog omissions never delete database rows. Invalid catalogs or records fail ingestion with a validation error.

Configure `THREATFLOW_RAW_DATA_DIR` and PostgreSQL connection settings in `.env`. Apply the existing migration to a local database, then run `uv run python -m threatflow.ingestion.cisa_ingestion`. Unit tests use mocks and temporary storage: `uv run python -m pytest tests/unit`. Database integration verification should use a dedicated isolated PostgreSQL database, never the development database.

## NVD CVE ingestion (Phase 4)

`threatflow.ingestion.nvd_ingestion` retrieves current CVE records from the official [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities). By default it requests records modified in the preceding 48 hours using UTC `lastModStartDate` and `lastModEndDate`. The overlap recovers delayed or retried runs; repeated records are safe because PostgreSQL bulk UPSERTs by `cve_id`. `ingest_nvd_cves(start=..., end=...)` accepts an explicit timezone-aware date range. NVD date ranges are limited to 120 days.

The client retrieves all pages using `startIndex`, `resultsPerPage`, and `totalResults`, validates pagination consistency, and fails if totals change during traversal. Each exact response page is stored through existing immutable Raw Storage before parsing at `data/raw/nvd/year=YYYY/month=MM/<sha256>.json`. Invalid required records fail ingestion. Duplicate CVEs use the record with the latest `lastModified`; equal-time conflicting projected data fails. CVSS is analytically projected by preferring valid 4.0, then 3.1, 3.0, then 2.0 metrics; this is not the only valid CVSS interpretation. Missing CVSS, CWE, or references is accepted.

Set `THREATFLOW_NVD_API_KEY` optionally; credentials are sent in the `apiKey` header and are not logged. Configure the API base URL, page size, lookback, timeouts, and retries with `THREATFLOW_NVD_*` and `THREATFLOW_HTTP_*`. Requests are paced separately from retry backoff. Run locally with `uv run python -m threatflow.ingestion.nvd_ingestion`. Unit tests use mocked HTTP responses; integration tests use isolated PostgreSQL 17 Testcontainers: `uv run python -m pytest tests/unit tests/integration`.

## EPSS daily scores (Phase 5)

The official [FIRST EPSS daily file](https://www.first.org/epss/data) is downloaded as a gzip CSV with `cve`, `epss`, and `percentile` columns. The complete original `.csv.gz` bytes are stored before decompression at `data/raw/epss/year=YYYY/month=MM/<sha256>.csv.gz` (or under `THREATFLOW_RAW_DATA_DIR`). The directory uses the **acquisition** month, while each database row uses the source **score date**. `epss_scores` uses `(cve_id, score_date)` as its primary key. Reprocessing updates corrected values for that date and keeps other dates and missing CVEs.

Set PostgreSQL credentials and, if needed, `THREATFLOW_RAW_DATA_DIR`, `THREATFLOW_HTTP_CONNECT_TIMEOUT`, `THREATFLOW_HTTP_READ_TIMEOUT`, and `THREATFLOW_HTTP_RETRIES` in `.env`. Apply the existing migration to your local database before manual ingestion. Run current ingestion with:

```sh
uv run python -m threatflow.ingestion.epss_ingestion
```

Run one historical date from the [official archive](https://github.com/empiricalsec/epss_scores) with:

```sh
uv run python -m threatflow.ingestion.epss_ingestion --score-date 2024-12-21
```

Current ingestion requires the CSV's `score_date` metadata; it fails if that date cannot be established. Historical ingestion uses the dated archive filename and rejects any conflicting embedded score date. Publication may occur after the score date begins; acquisition time never supplies the score date. Invalid or incomplete files remain in immutable Raw Storage for investigation, and database changes roll back on failure. Historical files before the archive's 2021-04-14 start are unavailable. Bulk historical orchestration is outside this phase.

Run unit and isolated PostgreSQL 17 Testcontainers tests with `uv run pytest -v`. Integration tests require a working Docker daemon; skipped tests do not establish successful verification.
