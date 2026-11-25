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

Build the local Airflow image, safely recreate the scheduler and DAG processor,
and verify that both containers run the current application image.

  --force       Recreate Airflow components even when tasks may be running.
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

configure_spark_java() {
  local java_home="${THREATFLOW_TEST_JAVA_HOME:-}"
  if [[ -z "$java_home" && -x /usr/libexec/java_home ]]; then
    java_home="$(/usr/libexec/java_home -v 21 2>/dev/null || true)"
  fi
  if [[ -z "$java_home" && -n "${JAVA_HOME:-}" ]]; then
    java_home="$JAVA_HOME"
  fi
  if [[ -z "$java_home" || ! -x "$java_home/bin/java" ]]; then
    echo "error: JDK 21 is required for local PySpark tests; install it or set THREATFLOW_TEST_JAVA_HOME" >&2
    exit 1
  fi

  local java_specification_version
  java_specification_version="$(
    "$java_home/bin/java" -XshowSettings:properties -version 2>&1 |
      awk -F= '/^[[:space:]]*java\.specification\.version =/ {gsub(/[[:space:]]/, "", $2); print $2}'
  )"
  if [[ "$java_specification_version" != "21" ]]; then
    echo "error: local PySpark tests require JDK 21, found ${java_specification_version:-unknown} at $java_home" >&2
    echo "error: set THREATFLOW_TEST_JAVA_HOME to a JDK 21 installation" >&2
    exit 1
  fi

  export JAVA_HOME="$java_home"
  export PATH="$JAVA_HOME/bin:$PATH"
  export PYSPARK_PYTHON="$project_root/.venv/bin/python"
  export PYSPARK_DRIVER_PYTHON="$project_root/.venv/bin/python"
  echo "==> Using JDK ${java_specification_version} for PySpark tests: $JAVA_HOME"
}

if [[ "$skip_tests" == false ]]; then
  configure_spark_java
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

echo "==> Recreating Airflow scheduler and DAG processor"
"${compose[@]}" up -d --force-recreate airflow-scheduler airflow-dag-processor

local_image_id="$(docker image inspect threatflow-airflow:3.1.0 --format '{{.Id}}')"
for service in airflow-scheduler airflow-dag-processor; do
  container_id="$(${compose[@]} ps -q "$service")"
  if [[ -z "$container_id" ]]; then
    echo "error: ${service} container was not created" >&2
    exit 1
  fi
  running_image_id="$(docker inspect "$container_id" --format '{{.Image}}')"
  if [[ "$local_image_id" != "$running_image_id" ]]; then
    echo "error: ${service} image ID does not match the newly built local image" >&2
    exit 1
  fi
done

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

echo "PASS: Airflow scheduler and DAG processor run the current image (${local_image_id})"
