"""Hourly additive CISA KEV change detection."""

from datetime import UTC, datetime, timedelta

from airflow.providers.standard.operators.python import ExternalPythonOperator
from airflow.sdk import DAG

from threatflow.orchestration.airflow_tasks import watch_cisa

with DAG(
    dag_id="cisa_watcher_hourly",
    schedule="0 * * * *",
    start_date=datetime(2025, 1, 1, tzinfo=UTC),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 2, "retry_delay": timedelta(minutes=5)},
    tags=["threatflow", "cisa", "watcher"],
) as dag:
    ExternalPythonOperator(
        task_id="watch_cisa",
        python_callable=watch_cisa,
        python="/opt/threatflow-venv/bin/python",
        expect_airflow=False,
        pool="cisa_api_pool",
        execution_timeout=timedelta(minutes=30),
    )
