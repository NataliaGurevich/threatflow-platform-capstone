#!/usr/bin/env bash

set -Eeuo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
project_root="$(dirname "$script_dir")"
cd "$project_root"

backup_dir="${THREATFLOW_BACKUP_DIR:-data/backups}"
retention_days="${THREATFLOW_BACKUP_RETENTION_DAYS:-14}"

if ! [[ "$retention_days" =~ ^[0-9]+$ ]] || ((retention_days < 1)); then
  echo "error: THREATFLOW_BACKUP_RETENTION_DAYS must be a positive integer" >&2
  exit 1
fi

if [[ ! -d "$backup_dir" ]]; then
  echo "error: backup directory does not exist: ${backup_dir}" >&2
  exit 1
fi

echo "Database backup retention report"
echo "Directory: ${backup_dir}"
echo "Retention: ${retention_days} days"
echo

expired_found=false

while IFS= read -r -d '' dump_path; do
  expired_found=true
  echo "Expired dump: ${dump_path}"

  if [[ -f "${dump_path}.sha256" ]]; then
    echo "Associated checksum: ${dump_path}.sha256"
  fi

  echo
done < <(
  find "$backup_dir" -type f -name '*.dump' \
    ! -newermt "${retention_days} days ago" -print0
)

if [[ "$expired_found" == false ]]; then
  echo "No expired database backups found."
fi

echo "No files were deleted."
