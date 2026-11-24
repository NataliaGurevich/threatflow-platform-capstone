#!/usr/bin/env bash
set -u

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

with_running_stack=false
if [[ "${1:-}" == "--with-running-stack" ]]; then
  with_running_stack=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: $0 [--with-running-stack]" >&2
  exit 2
fi

failures=0

run_required() {
  local label="$1"
  shift
  echo
  echo "==> $label"
  if "$@"; then
    echo "PASS: $label"
  else
    echo "FAIL: $label" >&2
    failures=$((failures + 1))
  fi
}

check_airflow_imports() {
  local output
  output="$(docker compose exec -T airflow-api-server airflow dags list-import-errors --output json)" || return 1
  [[ "$output" == "[]" ]]
}

run_required "Ruff" .venv/bin/python -m ruff check .
run_required "Unit and orchestration tests" .venv/bin/python -m pytest -q tests/unit tests/airflow/test_backfill_controller.py tests/airflow/test_orchestration.py
run_required "Compose configuration" docker compose config -q

echo
echo "==> Disposable PostgreSQL integration tests"
integration_output="$(mktemp)"
if .venv/bin/python -m pytest -q -rs tests/integration >"$integration_output" 2>&1; then
  cat "$integration_output"
  if grep -q "SKIPPED" "$integration_output"; then
    echo "NOT VERIFIED: PostgreSQL integration tests were skipped"
  else
    echo "PASS: Disposable PostgreSQL integration tests"
  fi
else
  cat "$integration_output" >&2
  echo "FAIL: Disposable PostgreSQL integration tests" >&2
  failures=$((failures + 1))
fi
rm -f "$integration_output"

if [[ "$with_running_stack" == true ]]; then
  run_required "Running PostgreSQL service" docker compose exec -T postgres pg_isready
  run_required "Airflow DAG import errors" check_airflow_imports
  run_required "Priority queue summary (read-only)" \
    sh -c 'docker compose exec -T postgres sh -c '\''psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'\'' < analytics/vulnerability_priority_summary.sql'
  run_required "Overall data-quality status (read-only)" \
    sh -c 'docker compose exec -T postgres sh -c '\''psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'\'' < analytics/data_quality_overall_status.sql'
fi

echo
if [[ "$failures" -eq 0 ]]; then
  echo "Capstone demo completed without failures. Review any NOT VERIFIED lines above."
  exit 0
fi

echo "Capstone demo completed with $failures failed step(s)." >&2
exit 1

