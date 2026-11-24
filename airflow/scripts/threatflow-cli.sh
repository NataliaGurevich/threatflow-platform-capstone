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
  help | --help | -h)
    cat <<'EOF'
ThreatFlow CLI container

Usage:
  docker compose run --rm threatflow-cli backfill [options]

Examples:
  docker compose run --rm threatflow-cli backfill --sources cisa --start 2025-01-01 --end 2025-01-31 --dry-run
EOF
    ;;
  *)
    echo "Unknown command: ${command_name}" >&2
    echo "Run 'docker compose run --rm threatflow-cli help' for usage." >&2
    exit 2
    ;;
esac
