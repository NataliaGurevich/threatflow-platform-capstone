"""Daily cisa ingestion."""

from datetime import UTC, datetime, timedelta

from airflow.providers.standard.operators.python import ExternalPythonOperator
from airflow.sdk import DAG

from threatflow.orchestration.airflow_tasks import daily

with DAG(
    dag_id="cisa_daily",
    schedule="0 4 * * *",
    start_date=datetime(2025, 1, 1, tzinfo=UTC),
    catchup=False,
    max_active_runs=1,
    default_args={"retries": 3, "retry_delay": timedelta(minutes=5)},
    tags=["threatflow"],
) as dag:
    ExternalPythonOperator(
        task_id="ingest_cisa",
        python_callable=daily,
        op_kwargs={
            "source": "cisa",
            "interval_start": "{{ dag_run.run_after.isoformat() }}",
            "interval_end": "{{ dag_run.run_after.isoformat() }}",
        },
        python="/opt/threatflow-venv/bin/python",
        expect_airflow=False,
        pool="cisa_api_pool",
        execution_timeout=timedelta(hours=3),
    )
