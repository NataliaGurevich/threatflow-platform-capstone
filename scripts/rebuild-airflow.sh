#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(dirname "$script_dir")"
cd "$project_root"

compose=(docker compose -f docker-compose.yml -f docker-compose.aws.yml)
force=false
skip_tests=false

usage() {
  cat <<'EOF'
Usage: scripts/rebuild-airflow.sh [--force] [--skip-tests]

Build the local Airflow image, safely recreate only the scheduler, and verify
that the running container contains the current application code and AWS login mount.

  --force       Recreate the scheduler even when Airflow reports running tasks.
  --skip-tests  Skip Ruff and focused Python tests (not recommended).
EOF
}

while (($# > 0)); do
  case "$1" in
    --force) force=true ;;
    --skip-tests) skip_tests=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required command not found: $1" >&2
    exit 1
  }
}

require_command docker
require_command shasum

if [[ "$skip_tests" == false ]]; then
  echo "==> Running Ruff"
  .venv/bin/python -m ruff check .
  echo "==> Running unit and Airflow tests"
  .venv/bin/python -m pytest -q tests/unit tests/airflow
fi

echo "==> Validating AWS-enabled Compose configuration"
"${compose[@]}" config -q

running_tasks="$(${compose[@]} exec -T postgres sh -c \
  'psql -U "$POSTGRES_USER" -d airflow -Atc "SELECT count(*) FROM task_instance WHERE state = '\''running'\''"' \
  2>/dev/null || printf 'unknown')"

if [[ "$running_tasks" == "unknown" ]]; then
  if [[ "$force" == false ]]; then
    echo "error: could not verify whether Airflow tasks are running; retry with --force only after checking the UI" >&2
    exit 1
  fi
elif [[ "$running_tasks" != "0" && "$force" == false ]]; then
  echo "error: Airflow reports ${running_tasks} running task(s); wait for completion or use --force" >&2
  exit 1
fi

echo "==> Building Airflow image"
"${compose[@]}" build airflow-scheduler

echo "==> Recreating Airflow scheduler"
"${compose[@]}" up -d --force-recreate airflow-scheduler

container_id="$(${compose[@]} ps -q airflow-scheduler)"
if [[ -z "$container_id" ]]; then
  echo "error: scheduler container was not created" >&2
  exit 1
fi

local_image_id="$(docker image inspect threatflow-airflow:3.1.0 --format '{{.Id}}')"
running_image_id="$(docker inspect "$container_id" --format '{{.Image}}')"
if [[ "$local_image_id" != "$running_image_id" ]]; then
  echo "error: scheduler image ID does not match the newly built local image" >&2
  exit 1
fi

host_source_sha="$(shasum -a 256 src/threatflow/ingestion/cisa_ingestion.py | awk '{print $1}')"
container_source_sha="$(${compose[@]} exec -T airflow-scheduler \
  /opt/threatflow-venv/bin/python -c \
  'import hashlib; from pathlib import Path; import threatflow.ingestion.cisa_ingestion as m; print(hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest())')"
if [[ "$host_source_sha" != "$container_source_sha" ]]; then
  echo "error: installed CISA ingestion source does not match the workspace" >&2
  exit 1
fi

"${compose[@]}" exec -T airflow-scheduler /opt/threatflow-venv/bin/python -c '
import inspect
import threatflow.ingestion.cisa_ingestion as module

source = inspect.getsource(module)
assert "\"request-mode\": \"snapshot\"" in source
assert "\"record-count\": str(len(records))" in source
print("PASS: current CISA Bronze metadata contract is installed")
'

echo "==> Verifying scheduler AWS identity"
"${compose[@]}" exec -T airflow-scheduler /opt/threatflow-venv/bin/python -c '
import boto3
identity = boto3.client("sts").get_caller_identity()
print(identity["Arn"])
assert not identity["Arn"].endswith(":root")
'

echo "PASS: Airflow scheduler is running the current local image (${running_image_id})"
