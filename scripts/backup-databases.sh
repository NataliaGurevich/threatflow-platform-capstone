#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(dirname "$script_dir")"
cd "$project_root"

backup_dir="${THREATFLOW_BACKUP_DIR:-data/backups}"
metabase_database="${METABASE_DB_NAME:-metabase}"
timestamp="$(date -u +%Y-%m-%dT%H%M%SZ)"

umask 077
mkdir -p "$backup_dir"

temporary_files=()

cleanup() {
  if ((${#temporary_files[@]} > 0)); then
    rm -f "${temporary_files[@]}"
  fi
}

trap cleanup EXIT HUP INT TERM

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required" >&2
  exit 1
fi

application_database="$(
  docker compose exec -T postgres sh -c 'printf "%s" "$POSTGRES_DB"'
)"

if [[ -z "$application_database" ]]; then
  echo "error: POSTGRES_DB is empty in the postgres container" >&2
  exit 1
fi

dump_database() {
  local database="$1"
  local label="$2"
  local filename="${label}-${timestamp}.dump"
  local final_path="${backup_dir}/${filename}"
  local temporary_path="${final_path}.tmp"
  local checksum_path="${final_path}.sha256"
  local checksum_temporary_path="${checksum_path}.tmp"

  if [[ -e "$final_path" || -e "$checksum_path" ]]; then
    echo "error: backup already exists for ${label} at ${timestamp}" >&2
    exit 1
  fi

  temporary_files+=("$temporary_path" "$checksum_temporary_path")

  echo "Creating backup for ${database}..."
  docker compose exec -T postgres sh -c \
    'exec pg_dump -U "$POSTGRES_USER" --format=custom --dbname="$1"' \
    sh "$database" >"$temporary_path"

  echo "Validating ${filename}..."
  docker compose exec -T postgres pg_restore --list \
    <"$temporary_path" >/dev/null

  mv "$temporary_path" "$final_path"
  (
    cd "$backup_dir"
    shasum -a 256 "$filename" >"${filename}.sha256.tmp"
  )
  mv "$checksum_temporary_path" "$checksum_path"

  echo "Created ${final_path}"
  echo "Created ${checksum_path}"
}

dump_database "$application_database" "$application_database"
dump_database "$metabase_database" "$metabase_database"

echo "Database backups completed successfully."
