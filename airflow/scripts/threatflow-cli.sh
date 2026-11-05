#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-help}"
if [[ $# -gt 0 ]]; then
  shift
fi

case "${command_name}" in
  backfill)
    exec /opt/threatflow-venv/bin/threatflow-backfill-range "$@"
    ;;
  backfill-status)
    exec /opt/threatflow-venv/bin/threatflow-backfill-status "$@"
    ;;
  rebuild-cisa-changes)
    exec /opt/threatflow-venv/bin/threatflow-build-cisa-changes "$@"
    ;;
  help | --help | -h)
    cat <<'EOF'
ThreatFlow CLI container

Usage:
  docker compose run --rm threatflow-cli backfill [options]
  docker compose run --rm --no-deps threatflow-cli backfill-status [options]
  docker compose run --rm threatflow-cli rebuild-cisa-changes

Examples:
  docker compose run --rm threatflow-cli backfill --sources cisa --start 2025-01-01 --end 2025-01-31 --dry-run
  docker compose run --rm --no-deps threatflow-cli backfill-status --checkpoint /opt/threatflow/data/backfill-checkpoint.json
  docker compose run --rm threatflow-cli rebuild-cisa-changes
EOF
    ;;
  *)
    echo "Unknown command: ${command_name}" >&2
    echo "Run 'docker compose run --rm threatflow-cli help' for usage." >&2
    exit 2
    ;;
esac
