#!/usr/bin/env bash
set -euo pipefail

metadata_days="${THREATFLOW_AIRFLOW_METADATA_RETENTION_DAYS:-90}"
xcom_days="${THREATFLOW_AIRFLOW_XCOM_RETENTION_DAYS:-30}"
log_days="${THREATFLOW_AIRFLOW_METADATA_RETENTION_DAYS:-90}"

metadata_cutoff="$(python -c "from datetime import UTC, datetime, timedelta; print((datetime.now(UTC) - timedelta(days=int('${metadata_days}'))).isoformat())")"
xcom_cutoff="$(python -c "from datetime import UTC, datetime, timedelta; print((datetime.now(UTC) - timedelta(days=int('${xcom_days}'))).isoformat())")"

airflow db clean \
  --clean-before-timestamp "${xcom_cutoff}" \
  --tables xcom \
  --skip-archive \
  --yes

airflow db clean \
  --clean-before-timestamp "${metadata_cutoff}" \
  --tables dag_run,dag_version,job,log,task_instance,task_instance_history,task_reschedule \
  --skip-archive \
  --yes

find /opt/airflow/logs -type f -mtime "+${log_days}" -delete
find /opt/airflow/logs -depth -type d -empty -delete
