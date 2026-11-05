# ThreatFlow CLI command reference

The recommended way to run the ThreatFlow CLI is through Docker Compose. This makes
the command use the same environment and configuration as the other project services.

## Main commands

| Command | Purpose | Reads | Changes | Important information |
| --- | --- | --- | --- | --- |
| `docker compose run --rm threatflow-cli help` | Shows the available commands | Nothing | Nothing | Safe command |
| `docker compose run --rm threatflow-cli backfill ...` | Starts a historical load through Airflow | Arguments, `.env`, checkpoint | Creates Airflow runs, updates the checkpoint, and loads raw files and PostgreSQL data | Always start with `--dry-run`; use a separate checkpoint for each plan |
| `docker compose run --rm --no-deps threatflow-cli backfill-status ...` | Shows backfill progress | Checkpoint JSON only | Nothing | Read-only; works without Airflow or PostgreSQL |
| `docker compose run --rm threatflow-cli rebuild-cisa-changes` | Rebuilds CISA change history from stored raw snapshots | `raw_artifacts` and CISA raw files | Atomically replaces the contents of `cisa_kev_changes` | Does not download data; does not modify the source raw files |
| `docker compose run --rm --no-deps threatflow-cli backup-databases` | Creates backups of `treat_flow` and `metabase` | Both PostgreSQL databases and `.env` | Creates `.dump` and `.sha256` files in `data/backups` | PostgreSQL must already be running; Airflow is not required; nothing is deleted |

## Historical backfill

Start with a safe plan preview:

```bash
docker compose run --rm threatflow-cli backfill \
  --sources nvd epss \
  --start 2025-01-01 \
  --end 2025-01-31 \
  --nvd-mode modified \
  --checkpoint /opt/threatflow/data/my-backfill.json \
  --dry-run
```

After reviewing the plan, remove `--dry-run`:

```bash
docker compose run --rm threatflow-cli backfill \
  --sources nvd epss \
  --start 2025-01-01 \
  --end 2025-01-31 \
  --nvd-mode modified \
  --checkpoint /opt/threatflow/data/my-backfill.json
```

| Argument | Meaning | Important information |
| --- | --- | --- |
| `--sources` | `nvd`, `cisa`, `epss` | Multiple sources can be specified |
| `--start` | Start date | Format: `YYYY-MM-DD` |
| `--end` | End date | The range is inclusive |
| `--nvd-mode modified` | NVD modifications during the range | Recommended for recovering missing updates |
| `--nvd-mode published` | CVEs published during the range | Does not recover later modifications |
| `--interval-days` | Outer window size | Defaults to 31 days |
| `--chunk-days` | NVD chunk size | Must respect NVD API limits |
| `--checkpoint` | State file | One checkpoint must be used for only one unchanged plan |
| `--dry-run` | Show the plan only | Does not contact Airflow or change data |

## Backfill status

```bash
docker compose run --rm --no-deps threatflow-cli backfill-status \
  --checkpoint /opt/threatflow/data/my-backfill.json \
  --stall-after-minutes 30
```

| Status | Meaning |
| --- | --- |
| `RUNNING` | An active window exists and its heartbeat is fresh |
| `STALLED` | The heartbeat is older than the configured threshold |
| `FAILED` | The active Airflow run is recorded as failed |
| `COMPLETED` | All windows are complete and no active window remains |
| `UNKNOWN` | The checkpoint cannot be classified reliably |

### `backfill-status` exit codes

| Code | Meaning |
| ---: | --- |
| `0` | `RUNNING` or `COMPLETED` |
| `1` | `FAILED` |
| `2` | `STALLED`, `UNKNOWN`, or invalid input |

Show the exit code of the most recent command:

```bash
echo $?
```

## Rebuilding CISA change history

```bash
docker compose run --rm threatflow-cli rebuild-cisa-changes
```

The command:

- does not contact GitHub;
- reads previously stored CISA snapshots;
- builds `baseline`, `added`, `modified`, and `removed` events;
- replaces the derived table in one transaction;
- is safe to run repeatedly;
- does not delete raw files.

This operation writes to PostgreSQL. The `cisa_kev_changes` table is derived and can be
rebuilt from the raw snapshots.

## Database backup

```bash
docker compose run --rm --no-deps threatflow-cli backup-databases
```

Output:

```text
data/backups/
├── treat_flow-<UTC timestamp>.dump
├── treat_flow-<UTC timestamp>.dump.sha256
├── metabase-<UTC timestamp>.dump
└── metabase-<UTC timestamp>.dump.sha256
```

| Argument | Default | Purpose |
| --- | --- | --- |
| `--output-dir` | `/opt/threatflow/data/backups` | Directory inside the CLI container |
| `--metabase-database` | `METABASE_DB_NAME` or `metabase` | Metabase database name |
| `--connect-timeout-seconds` | `10` | PostgreSQL connection timeout |

### `backup-databases` exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Both databases were backed up and validated successfully |
| `1` | Connection, `pg_dump`, validation, or filesystem failure |
| `2` | Invalid CLI arguments |

The command does not back up:

- `data/raw`;
- Airflow metadata;
- Airflow logs;
- `MB_ENCRYPTION_SECRET_KEY`;
- backups to an external disk.

PostgreSQL must be running before the command starts. `--no-deps` intentionally avoids
starting Airflow and other Compose dependencies.

## Retention report

The retention report is a separate host script, not a container CLI command:

```bash
./scripts/report-expired-database-backups.sh
```

| Property | Behavior |
| --- | --- |
| Retention | 14 days |
| Search scope | `*.dump` files only |
| Raw archives | Not considered |
| Deletion | Never performed |
| Result | Lists expired dumps and their associated checksums |

Override the window for one run:

```bash
THREATFLOW_BACKUP_RETENTION_DAYS=30 \
  ./scripts/report-expired-database-backups.sh
```

## Docker Compose flags

| Flag | Meaning |
| --- | --- |
| `run` | Creates a one-shot container for the command |
| `--rm` | Removes the one-shot container afterward; files in the mounted `data` directory remain |
| `--no-deps` | Does not start Compose dependencies such as Airflow |
| `-T` | Disables the pseudo-terminal; important when redirecting a binary dump |
| `exec` | Runs a command inside an existing container |

## Safe usage rules

1. Always run a large backfill with `--dry-run` first.
2. Do not reuse one checkpoint for different date ranges or source sets.
3. Do not pass passwords through command-line arguments.
4. After a database backup, verify its `.sha256` file and periodically perform a test
   restore into a separate database.
5. Keep `MB_ENCRYPTION_SECRET_KEY` separately in a password manager.
6. Copy validated backups to a separate disk or protected external storage.
7. Do not use `--remove-orphans` or destructive cleanup without checking the exact
   targets first.
